import datetime
import enum
from flask import g, Flask
from sqlalchemy.types import ARRAY

from common.config import conf
from service import db
# get the logger instance -
from common.logs import get_logger
logger = get_logger(__name__)


class Site(db.Model):
    __tablename__ = 'site'
    site_id = db.Column(db.String, primary_key=True)
    primary = db.Column(db.Boolean, nullable=False, default=False)

    # only needs to be set if primary=True
    base_url = db.Column(db.String, nullable=True, unique=True)

    tenant_base_url_template = db.Column(db.String, nullable=True, unique=True)
    site_master_tenant_id = db.Column(db.String, nullable=False)
    services = db.Column(ARRAY(db.String), unique=False, nullable=False)

    def __repr__(self):
        return f'{self.site_id}'

    @property
    def serialize(self):
        return {
            "site_id": self.site_id,
            "primary": self.primary,
            "base_url": self.base_url,
            "tenant_base_url_template": self.tenant_base_url_template,
            "site_master_tenant_id": self.site_master_tenant_id,
            "services": self.services
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
    try:
        tenants = Tenant.query.all()
        return [t.serialize for t in tenants]
    except Exception as e:
        logger.info(f"WARNING - got exception trying to calculate the tenants; this better be the migration code "
                    f"running. exception: {e}")
        db.session.rollback()
        return []


def ensure_primary_site_present():
    """
        Ensure the dev tenant is registered in the local db.
        :return:
        """
    try:
        existing_primary = Site.query.filter_by(primary=True).first()
        if existing_primary:
        # a primary site already exists, we don't need to make one
            return
    except Exception as e:
        logger.debug('no existing primary')
    try:
        add_primary_site(site_id='tacc',
                         base_url='https://tapis.io',
                         tenant_base_url_template='https://${tenant_id}.tapis.io',
                         services=['systems', 'files', 'security', 'tokens', 'streams', 'authenticator', 'meta', 'actors'])

    except Exception as e:
        logger.error(f'Got exception trying to add the primary site. e: {e}')
        # we have to swallow this exception as well because it is possible this code is running from within the
        # migrations container before the migrations have tun to create the table.
        db.session.rollback()


def ensure_master_tenant_present():
    """
    Ensure the master tenant is registered in the local db.
    :return: 
    """
    ensure_primary_site_present()
    # if the master tenant is already registered, just escape 0
    tenants = get_tenants()
    for tenant in tenants:
        if tenant.get('tenant_id') == 'master':
            return
    try:
        add_owner(name='CIC Support', email='CICSupport@tacc.utexas.edu', institution='UT Austin')
    except Exception as e:
        logger.info(f'Got exception trying to add an owner; e: {e}')
        # we swallow this exception and try to add the tenant since it is possible the owner was present but not the
        # tenant.
        db.session.rollback()
    # use the base URL configured for this Tenants API service.
    base_url = conf.service_tenant_base_url
    site_id = 'tacc'
    try:
        # the master tenant
        add_tenant(tenant_id='master',
                   base_url=base_url,
                   is_owned_by_associate_site=False,
                   site_id=site_id,
                   token_service=f'{base_url}/v3/tokens',
                   security_kernel=f'{base_url}/v3/security',
                   authenticator=f'{base_url}/v3/oauth2',
                   owner='CICSupport@tacc.utexas.edu',
                   service_ldap_connection_id=None,
                   user_ldap_connection_id=None,
                   description='The master tenant.')
    except Exception as e:
        logger.error(f'Got exception trying to add the dev tenant. e: {e}')
        # we have to swallow this exception as well because it is possible this code is running from within the
        # migrations container before the migrations have tun to create the table.
        db.session.rollback()


def ensure_dev_tenant_present():
    """
    Ensure the dev tenant is registered in the local db.
    :return:
    """
    ensure_primary_site_present()
    tenants = get_tenants()
    for tenant in tenants:
        if tenant.get('tenant_id') == 'dev':
            return
    base_url = conf.service_tenant_base_url.replace('master', 'dev')
    # add the dev ldap
    try:
        add_ldap(ldap_id="tapis-dev",
                 url="ldap://authenticator-ldap",
                 port=389,
                 use_ssl=False,
                 user_dn="ou=tenants.dev,dc=tapis",
                 bind_dn="cn=admin,dc=tapis",
                 bind_credential="ldap.tapis-dev.password",
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
                   is_owned_by_associate_site=False,
                   site_id='tacc',
                   token_service=f'{base_url}/v3/tokens',
                   security_kernel=f'{base_url}/v3/security',
                   authenticator=f'{base_url}/v3/oauth2',
                   owner='CICSupport@tacc.utexas.edu',
                   service_ldap_connection_id=None,
                   user_ldap_connection_id='tapis-dev',
                   description='The dev tenant.')
    except Exception as e:
        logger.error(f'Got exception trying to add the dev tenant. e: {e}')
        # we have to swallow this exception as well because it is possible this code is running from within the
        # migrations container before the migrations have tun to create the table.
        db.session.rollback()

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
                     site_master_tenant_id,
                     services):
    """
    Convenience function for adding the (one and only) primary site directly to the db.
    :return:
    """

    site = Site(site_id=site_id,
                base_url=base_url,
                primary=True,
                tenant_base_url_template=tenant_base_url_template,
                site_master_tenant_id=site_master_tenant_id,
                services=services)
    db.session.add(site)
    db.session.commit()


def add_tenant(tenant_id,
               base_url,
               is_owned_by_associate_site,
               site_id,
               token_service,
               security_kernel,
               authenticator,
               owner,
               service_ldap_connection_id,
               user_ldap_connection_id,
               description):
    """
    Convenience function for adding a tenant directly to the db.
    :return:
    """
    tenant = Tenant(tenant_id=tenant_id,
                        base_url=base_url,
                        is_owned_by_associate_site=is_owned_by_associate_site,
                        site_id=site_id,
                        token_service=token_service,
                        security_kernel=security_kernel,
                        authenticator=authenticator,
                        owner=owner,
                        service_ldap_connection_id=service_ldap_connection_id,
                        user_ldap_connection_id=user_ldap_connection_id,
                        description=description,
                        create_time=datetime.datetime.utcnow(),
                        last_update_time=datetime.datetime.utcnow())
    db.session.add(tenant)
    db.session.commit()


class Tenant(db.Model):
    __tablename__ = 'tenants'
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.String(50), unique=True, nullable=False)
    base_url = db.Column(db.String(2000), unique=True, nullable=False)
    is_owned_by_associate_site = db.Column(db.Boolean, unique=False, nullable=False)
    site_id = db.Column(db.String(50), primary_key=False, nullable=False)
    token_service = db.Column(db.String(2000), unique=False, nullable=False)
    security_kernel = db.Column(db.String(2000), unique=False, nullable=False)
    authenticator = db.Column(db.String(2000), unique=False, nullable=False)
    owner = db.Column(db.String(120), db.ForeignKey('tenantOwners.email'), nullable=False)
    create_time = db.Column(db.DateTime, nullable=False)
    last_update_time = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)

    # ldap connections are not required if the tenant will use an alternative mechanism for authenticating accounts -
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
            'is_owned_by_associate_site': self.is_owned_by_associate_site,
            'site_id': self.site_id,
            'token_service': self.token_service,
            'security_kernel': self.security_kernel,
            'authenticator': self.authenticator,
            'owner': self.owner,
            'service_ldap_connection_id': self.service_ldap_connection_id,
            'user_ldap_connection_id': self.user_ldap_connection_id,
            'public_key': self.get_public_key(),
            'description': self.description,
            "create_time": self.create_time,
            "last_update_time": self.last_update_time,

        }
        # the following code references the the flask thread-local object, g, but this will throw a runtime error
        # if executed outside of the application context. that will happen at service initialization when
        # get_tenants() is called to determine the list of tenants in the system.
        #
        # UPDATE: 3/2020: sending back ldap properties regardless of authentication since some services
        #                 including the authenticators will need the fields to determine how they should init.
        # try:
        #     if hasattr(g, 'no_token') and g.no_token:
        #         d.pop('service_ldap_connection_id')
        #         d.pop('user_ldap_connection_id')
        # except RuntimeError:
        #     pass
        return d

    def get_public_key(self):
        """
        Return the public key associated with this tenant.
        :return: (str) The public key, as a string.
        """
        # todo - This ultimately needs to be changed to look up the public key from the SK.
        return conf.dev_jwt_public_key