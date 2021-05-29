import datetime
import enum
import json
from flask import g, Flask
from sqlalchemy.types import ARRAY

from common.config import conf
from service import db, MIGRATIONS_RUNNING
# get the logger instance -
from common.logs import get_logger
logger = get_logger(__name__)

public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz7rr5CsFM7rHMFs7uKIdcczn0uL4ebRMvH8pihrg1tW/fp5Q+5ktltoBTfIaVDrXGF4DiCuzLsuvTG5fGElKEPPcpNqaCzD8Y1v9r3tfkoPT3Bd5KbF9f6eIwrGERMTs1kv7665pliwehz91nAB9DMqqSyjyKY3tpSIaPKzJKUMsKJjPi9QAS167ylEBlr5PECG4slWLDAtSizoiA3fZ7fpngfNr4H6b2iQwRtPEV/EnSg1N3Oj1x8ktJPwbReKprHGiEDlqdyT6j58l/I+9ihR6ettkMVCq7Ho/bsIrwm5gP0PjJRvaD5Flsze7P4gQT37D1c5nbLR+K6/T0QTiyQIDAQAB\n-----END PUBLIC KEY-----"

class Site(db.Model):
    __tablename__ = 'site'
    site_id = db.Column(db.String, primary_key=True)
    primary = db.Column(db.Boolean, nullable=False, default=False)

    # only needs to be set if primary=True
    base_url = db.Column(db.String, nullable=True, unique=True)

    tenant_base_url_template = db.Column(db.String, nullable=True, unique=True)
    site_admin_tenant_id = db.Column(db.String, nullable=False)
    services = db.Column(ARRAY(db.String), unique=False, nullable=False)

    create_time = db.Column(db.DateTime, nullable=False)
    last_update_time = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    created_by = db.Column(db.String(120), unique=False, nullable=False)
    last_updated_by = db.Column(db.String(120), unique=False, nullable=False)

    def __repr__(self):
        return f'{self.site_id}'

    @property
    def serialize(self):
        return {
            "site_id": self.site_id,
            "primary": self.primary,
            "base_url": self.base_url,
            "tenant_base_url_template": self.tenant_base_url_template,
            "site_admin_tenant_id": self.site_admin_tenant_id,
            "services": self.services,
            "create_time": str(self.create_time),
            "created_by": self.created_by,
            "last_update_time": str(self.last_update_time),
            "last_updated_by": self.last_updated_by
        }


class TenantOwner(db.Model):
    __tablename__ = 'tenantOwners'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(80), unique=False, nullable=False)
    institution = db.Column(db.String(80), unique=False, nullable=False)
    create_time = db.Column(db.DateTime, nullable=False)
    last_update_time = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)

    def __repr__(self):
        return f'{self.email}, {self.institution}'

    @property
    def serialize(self):
        return {
            "email": self.email,
            "name": self.name,
            "institution": self.institution,
            "create_time": self.create_time,
            "last_update_time": self.last_update_time,
        }


class LDAPAccountTypes(enum.Enum):
    user = 'user'
    service = 'service'

    def __repr__(self):
        if self.user:
            return 'user'
        return 'service'

    def __str__(self):
        return self.__repr__()

    @property
    def serialize(self):
        return str(self)


class LDAPConnection(db.Model):
    __tablename__ = 'ldap_connections'
    id = db.Column(db.Integer, primary_key=True)
    ldap_id = db.Column(db.String(50), unique=True, nullable=False)
    url = db.Column(db.String(2000), unique=False, nullable=False)
    port = db.Column(db.Integer, unique=False, nullable=False)
    use_ssl = db.Column(db.Boolean, unique=False, nullable=False)
    user_dn = db.Column(db.String(200), unique=False, nullable=False)
    bind_dn = db.Column(db.String(200), unique=False, nullable=False)
    bind_credential = db.Column(db.String(200), unique=False, nullable=False)
    account_type = db.Column(db.Enum(LDAPAccountTypes), unique=False, nullable=False)
    create_time = db.Column(db.DateTime, nullable=False)
    last_update_time = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)

    @property
    def serialize(self):
        return {
            'ldap_id': self.ldap_id,
            'url': self.url,
            'port': self.port,
            'user_dn': self.user_dn,
            'bind_dn': self.bind_dn,
            'use_ssl': self.use_ssl,
            'bind_credential': self.bind_credential,
            'account_type': self.account_type.serialize,
            "create_time": self.create_time,
            "last_update_time": self.last_update_time,
        }


def get_tenants():
    """
    Convenience function to return the list of tenants in the db.
    :return: (list[dict]) List of tenant descriptions.
    """
    if MIGRATIONS_RUNNING:
        logger.info("detected that migrations are running.. skipping calculation of tenants")
        return []
    try:
        tenants = Tenant.query.all()
        return [t.serialize for t in tenants]
    except Exception as e:
        logger.info(f"WARNING - got exception trying to calculate the tenants; this better be the migration code "
                    f"running. exception: {e}")
        db.session.rollback()
        return []


def get_sites():
    """
    Convenience function to return the list of sites in the db.
    :return: (list[dict]) List of site descriptions.
    """
    if MIGRATIONS_RUNNING:
        logger.info("detected that migrations are running.. skipping calculation of sites")
        return []
    try:
        sites = Site.query.all()
        return [s.serialize for s in sites]
    except Exception as e:
        logger.info(f"WARNING - got exception trying to calculate the sites; this better be the migration code "
                    f"running. exception: {e}")
        db.session.rollback()
        return []


def ensure_primary_site_present():
    """
        Ensure the dev tenant is registered in the local db.
        :return:
        """
    logger.debug("top of ensure_primary_site_present")
    try:
        existing_primary = Site.query.filter_by(primary=True).first()
        if existing_primary:
        # a primary site already exists, we don't need to make one
            logger.debug("a primary site already exists; escaping.")
            return
    except Exception as e:
        logger.debug('no existing primary')
    # the primary_site_admin_tenant_base_url has the form
    # https://admin.develop.tapis.io OR
    # https://admin.staging.tapis.io etc..
    # replace the "V." with "" to get the site base URL:
    base_url = conf.primary_site_admin_tenant_base_url.replace("admin.", "")
    # and replace "admin" with ${tenant_id} to get the template:
    tenant_base_url_template = conf.primary_site_admin_tenant_base_url.replace("admin", "${tenant_id}")
    logger.info(f"adding primary site with base_url: {base_url} and "
                f"tenant_base_url_template: {tenant_base_url_template}")
    try:
        add_primary_site(site_id='tacc',
                         base_url=base_url,
                         tenant_base_url_template=tenant_base_url_template,
                         site_admin_tenant_id='admin',
                         services=['systems', 'files', 'security', 'tokens', 'streams', 'authenticator', 'meta', 'actors'])

    except Exception as e:
        logger.error(f'Got exception trying to add the primary site. e: {e}')
        # we have to swallow this exception as well because it is possible this code is running from within the
        # migrations container before the migrations have tun to create the table.
        db.session.rollback()


def ensure_admin_tenant_present():
    """
    Ensure the admin tenant is registered in the local db.
    :return: 
    """
    logger.debug("top of ensure_admin_tenant_present")
    ensure_primary_site_present()
    # if the admin tenant is already registered, just escape 0
    tenants = get_tenants()
    for tenant in tenants:
        if tenant.get('tenant_id') == 'admin':
            return
    try:
        add_owner(name='CIC Support', email='CICSupport@tacc.utexas.edu', institution='UT Austin')
    except Exception as e:
        logger.info(f'Got exception trying to add an owner; e: {e}')
        # we swallow this exception and try to add the tenant since it is possible the owner was present but not the
        # tenant.
        db.session.rollback()
    # use the base URL configured for this Tenants API service.
    base_url = conf.primary_site_admin_tenant_base_url
    site_id = 'tacc'
    try:
        # the admin tenant
        add_tenant(tenant_id='admin',
                   base_url=base_url,
                   site_id=site_id,
                   token_service=f'{base_url}/v3/tokens',
                   security_kernel=f'{base_url}/v3/security',
                   authenticator=f'{base_url}/v3/oauth2',
                   owner='CICSupport@tacc.utexas.edu',
                   admin_user='admin',
                   # in the admin tenant, no additional services should have the token_generator role
                   token_gen_services=[],
                   service_ldap_connection_id=None,
                   user_ldap_connection_id=None,
                   description='The admin tenant.',
                   status='inactive',
                   public_key=public_key)
    except Exception as e:
        logger.error(f'Got exception trying to add the admin tenant. e: {e}')
        # we have to swallow this exception as well because it is possible this code is running from within the
        # migrations container before the migrations have tun to create the table.
        db.session.rollback()
    logger.info("admin tenant added")


def ensure_dev_tenant_present():
    """
    Ensure the dev tenant is registered in the local db.
    :return:
    """
    logger.debug("top of ensure_dev_tenant_present")
    ensure_primary_site_present()
    tenants = get_tenants()
    for tenant in tenants:
        if tenant.get('tenant_id') == 'dev':
            return
    base_url = conf.primary_site_admin_tenant_base_url.replace('admin', 'dev')
    # add the dev ldap
    try:
        add_ldap(ldap_id="tapis-dev",
                 url="ldap://authenticator-ldap",
                 port=389,
                 use_ssl=False,
                 user_dn="ou=tenants.dev,dc=tapis",
                 bind_dn="cn=admin,dc=tapis",
                 bind_credential="ldap.tapis-dev",
                 account_type="user")
    except Exception as e:
        logger.info(f'Got exception trying to add an ldap; e: {e}')
        # we swallow this exception and try to add the tenant since it is possible the ldap was present but not the
        # tenant.
        db.session.rollback()
    try:
        # the dev tenant
        add_tenant(tenant_id='dev',
                   base_url=base_url,
                   site_id='tacc',
                   token_service=f'{base_url}/v3/tokens',
                   security_kernel=f'{base_url}/v3/security',
                   authenticator=f'{base_url}/v3/oauth2',
                   owner='CICSupport@tacc.utexas.edu',
                   admin_user='admin',
                   token_gen_services=['abaco', 'authenticator'],
                   service_ldap_connection_id=None,
                   user_ldap_connection_id='tapis-dev',
                   description='The dev tenant.',
                   status='inactive',
                   public_key=public_key)
    except Exception as e:
        logger.error(f'Got exception trying to add the dev tenant. e: {e}')
        # we have to swallow this exception as well because it is possible this code is running from within the
        # migrations container before the migrations have tun to create the table.
        db.session.rollback()
    logger.info("dev tenant added")


def add_owner(name, email, institution):
    """
    Convenience function for adding a tenant owner directly to the db.
    :return:
    """
    owner = TenantOwner(name=name,
                        email=email,
                        institution=institution,
                        create_time=datetime.datetime.utcnow(),
                        last_update_time=datetime.datetime.utcnow()
                        )
    db.session.add(owner)
    db.session.commit()


def add_ldap(ldap_id, account_type, bind_credential, bind_dn, port, url, use_ssl, user_dn):
    """
    Convenience function fot adding an ldap object directly to the db.
    :return:
    """
    ldap = LDAPConnection(ldap_id=ldap_id,
                          account_type=account_type,
                          bind_credential=bind_credential,
                          bind_dn=bind_dn,
                          port=port,
                          url=url,
                          use_ssl=use_ssl,
                          user_dn=user_dn,
                          create_time=datetime.datetime.utcnow(),
                          last_update_time=datetime.datetime.utcnow())
    db.session.add(ldap)
    db.session.commit()


def add_primary_site(site_id,
                     base_url,
                     tenant_base_url_template,
                     site_admin_tenant_id,
                     services):
    """
    Convenience function for adding the (one and only) primary site directly to the db.
    :return:
    """

    site = Site(site_id=site_id,
                base_url=base_url,
                primary=True,
                tenant_base_url_template=tenant_base_url_template,
                site_admin_tenant_id=site_admin_tenant_id,
                services=services,
                created_by='tenants@admin',
                create_time=datetime.datetime.now(),
                last_updated_by='tenants@admin',
                last_update_time=datetime.datetime.now())
    db.session.add(site)
    db.session.commit()


def add_tenant(tenant_id,
               base_url,
               site_id,
               token_service,
               security_kernel,
               authenticator,
               owner,
               admin_user,
               token_gen_services,
               service_ldap_connection_id,
               user_ldap_connection_id,
               description,
               status,
               public_key):
    """
    Convenience function for adding a tenant directly to the db.
    :return:
    """
    tenant = Tenant(tenant_id=tenant_id,
                        base_url=base_url,
                        site_id=site_id,
                        token_service=token_service,
                        security_kernel=security_kernel,
                        authenticator=authenticator,
                        owner=owner,
                        admin_user=admin_user,
                        token_gen_services=token_gen_services,
                        service_ldap_connection_id=service_ldap_connection_id,
                        user_ldap_connection_id=user_ldap_connection_id,
                        description=description,
                        create_time=datetime.datetime.utcnow(),
                        created_by='tenants@admin',
                        last_update_time=datetime.datetime.utcnow(),
                        last_updated_by='tenants@admin',
                        status=status,
                        public_key=public_key
                    )
    db.session.add(tenant)
    db.session.commit()


class TenantStatusTypes(enum.Enum):
    """
    Enum class of possible statuses for a tenant.
    """
    draft = 'DRAFT'
    active = 'ACTIVE'
    inactive = 'INACTIVE'

    def __repr__(self):
        if self is TenantStatusTypes.draft:
            return 'DRAFT'
        elif self is TenantStatusTypes.active:
            return 'ACTIVE'
        return 'INACTIVE'

    def __str__(self):
        return self.__repr__()

    @property
    def serialize(self):
        return str(self)


class Tenant(db.Model):
    __tablename__ = 'tenants'
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(50), unique=True, nullable=False)
    base_url = db.Column(db.String(2000), unique=True, nullable=False)
    site_id = db.Column(db.String(50), primary_key=False, nullable=False)
    status = db.Column(db.Enum(TenantStatusTypes), unique=False, nullable=False)
    token_service = db.Column(db.String(2000), unique=False, nullable=False)
    security_kernel = db.Column(db.String(2000), unique=False, nullable=False)
    authenticator = db.Column(db.String(2000), unique=False, nullable=False)
    owner = db.Column(db.String(120), db.ForeignKey('tenantOwners.email'), nullable=False)
    admin_user = db.Column(db.String(120), unique=False, nullable=False)
    token_gen_services = db.Column(ARRAY(db.String), unique=False, nullable=False)
    create_time = db.Column(db.DateTime, nullable=False)
    last_update_time = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    created_by = db.Column(db.String(120), unique=False, nullable=False)
    last_updated_by = db.Column(db.String(120), unique=False, nullable=False)
    public_key = db.Column(db.String(10000), unique=False, nullable=True)
    # NOTE: ldap connections are not required if the tenant will use an alternative mechanism for authenticating
    # accounts:
    service_ldap_connection_id = db.Column(db.String(50), db.ForeignKey('ldap_connections.ldap_id'), nullable=True)
    user_ldap_connection_id = db.Column(db.String(50), db.ForeignKey('ldap_connections.ldap_id'), nullable=True)
    description = db.Column(db.String(1000), unique=False, nullable=True)

    def __repr__(self):
        return f'{self.tenant_id}: {self.description}'

    @property
    def serialize(self):
        d = {
            'tenant_id': self.tenant_id,
            'base_url': self.base_url,
            'site_id': self.site_id,
            'token_service': self.token_service,
            'security_kernel': self.security_kernel,
            'authenticator': self.authenticator,
            'owner': self.owner,
            'admin_user': self.admin_user,
            'token_gen_services': self.token_gen_services,
            'service_ldap_connection_id': self.service_ldap_connection_id,
            'user_ldap_connection_id': self.user_ldap_connection_id,
            'public_key': self.public_key,
            'status': self.status.serialize,
            'description': self.description,
            'create_time': str(self.create_time),
            'created_by': self.created_by,
            'last_updated_by': self.last_updated_by,
            'last_update_time': str(self.last_update_time),
        }
        return d

    def get_public_key(self):
        """
        Return the public key associated with this tenant.
        :return: (str) The public key, as a string.
        """
        # todo - This ultimately needs to be changed to look up the public key from the SK.
        return conf.dev_jwt_public_key


class TenantHistory(db.Model):
    __tablename__ = 'tenants_history'
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(50), db.ForeignKey('tenants.tenant_id'), nullable=False)
    update_time = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_by = db.Column(db.String(120), unique=False, nullable=False)
    updates_as_json = db.Column(db.String(10000), unique=False, nullable=False)

    @property
    def serialize(self):
        d = {
            'tenant_id': self.tenant_id,
            'update_time': str(self.update_time),
            'updated_by': self.updated_by,
            'updates': json.loads(self.updates_as_json)
        }
        return d
