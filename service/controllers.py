import datetime
from flask import request
from flask_restful import Resource
from openapi_core.shortcuts import RequestValidator
from openapi_core.wrappers.flask import FlaskOpenAPIRequest
# import psycopg2
import sqlalchemy
from service import db
from common import utils, errors
from service.models import LDAPConnection, TenantOwner, Tenant, Site

# get the logger instance -
from common.logs import get_logger
logger = get_logger(__name__)


class SitesResource(Resource):

    def get(self):
        logger.debug("top of GET /sites")
        sites = Site.query.all()
        return utils.ok(result=[s.serialize for s in sites], msg="Sites retrieved successfully.")

    def post(self):
        logger.debug("top of POST /sites")
        validator = RequestValidator(utils.spec)
        result = validator.validate(FlaskOpenAPIRequest(request))
        if result.errors:
            raise errors.ResourceError(msg=f'Invalid POST data: {result.errors}')
        validated_params = result.parameters
        validated_body = result.body
        logger.debug(f'validated_body: {dir(validated_body)}')
        site = Site(site_id=validated_body.site_id,
                    primary=validated_body.primary,
                    base_url=validated_body.base_url,
                    tenant_base_url_template=validated_body.tenant_base_url_template,
                    site_master_tenant_id=validated_body.site_master_tenant_id,
                    services=validated_body.services)
        db.session.add(site)
        try:
            db.session.commit()
        except (sqlalchemy.exc.SQLAlchemyError, sqlalchemy.exc.DBAPIError) as e:
            msg = utils.get_message_from_sql_exc(e)
            raise errors.ResourceError(f"Invalid POST data; {msg}")
        return utils.ok(result=site.serialize,
                        msg="Site object created successfully.")


class SiteResource(Resource):
    """
    Work with a single Site object.
    """

    def get(self, site_id):
        logger.debug(f"top of GET /sites/{site_id}")
        site = Site.query.filter_by(site_id=site_id).first()
        if not site:
            raise errors.ResourceError(msg=f'No site found with site_id {site_id}.')
        return utils.ok(result=site.serialize, msg='Site retrieved successfully.')

    def delete(self, site_id):
        logger.debug(f"top of DELETE /sites/{site_id}")
        tenant = Tenant.query.filter_by(tenant_id=site_id).first()
        if not tenant:
            logger.debug(f"Did not find a site with id {site_id}. Returning an error.")
            raise errors.ResourceError(msg=f'No site found with site_id {site_id}.')
        logger.debug("site found; issuing delete and commit.")
        db.session.delete(tenant)
        db.session.commit()
        return utils.ok(result=None, msg=f'Site {site_id} deleted successfully.')


class LDAPsResource(Resource):
    """
    Work with LDAP connection objects
    """

    # @swag_from("resources/ldaps/list.yml")
    def get(self):
        logger.debug("top of GET /ldaps")
        ldaps = LDAPConnection.query.all()
        return utils.ok(result=[l.serialize for l in ldaps], msg="LDAPs retrieved successfully.")

    def post(self):
        logger.debug("top of POST /ldaps")
        validator = RequestValidator(utils.spec)
        result = validator.validate(FlaskOpenAPIRequest(request))
        if result.errors:
            raise errors.ResourceError(msg=f'Invalid POST data: {result.errors}.')
        validated_params = result.parameters
        validated_body = result.body
        logger.debug(f"validated_body: {dir(validated_body)}")
        ldap = LDAPConnection(ldap_id=validated_body.ldap_id,
                              url=validated_body.url,
                              port=validated_body.port,
                              use_ssl=validated_body.use_ssl,
                              user_dn=validated_body.user_dn,
                              bind_dn=validated_body.bind_dn,
                              bind_credential=validated_body.bind_credential,
                              account_type=validated_body.account_type,
                              create_time=datetime.datetime.utcnow(),
                              last_update_time = datetime.datetime.utcnow())
        db.session.add(ldap)
        try:
            db.session.commit()
        except (sqlalchemy.exc.SQLAlchemyError, sqlalchemy.exc.DBAPIError) as e:
            msg = utils.get_message_from_sql_exc(e)
            raise errors.ResourceError(f"Invalid POST data; {msg}")
        return utils.ok(result=ldap.serialize,
                        msg="LDAP object created successfully.")


class LDAPResource(Resource):
    """
    Work with a single LDAP connection object.
    """

    def get(self, ldap_id):
        logger.debug(f"top of GET /ldaps/{ldap_id}")
        ldap = LDAPConnection.query.filter_by(ldap_id=ldap_id).first()
        if not ldap:
            raise errors.ResourceError(msg=f'No LDAP object found with id {ldap_id}.')
        return utils.ok(result=ldap.serialize, msg='LDAP object retrieved successfully.')

    def delete(self, ldap_id):
        logger.debug(f"top of DELETE /ldaps/{ldap_id}")
        ldap = LDAPConnection.query.filter_by(ldap_id=ldap_id).first()
        if not ldap:
            raise errors.ResourceError(msg=f'No LDAP object found with id {ldap_id}.')
        # ensure ldap is not references by existing tenant:
        tenants = Tenant.query.filter_by(service_ldap_connection_id=ldap_id).first()
        if tenants:
            logger.info("LDAP currently in use by tenants.")
            raise errors.ResourceError(msg='This LDAP is in use by existing tenants; delete the tenants firts.')
        tenants = Tenant.query.filter_by(user_ldap_connection_id=ldap_id).first()
        if tenants:
            logger.info("LDAP currently in use by tenants.")
            raise errors.ResourceError(msg='This LDAP is in use by existing tenants; delete the tenants firts.')
        try:
            db.session.delete(ldap)
            db.session.commit()
        except (sqlalchemy.exc.SQLAlchemyError, sqlalchemy.exc.DBAPIError) as e:
            msg = utils.get_message_from_sql_exc(e)
            raise errors.ResourceError(f"Invalid POST data; {msg}")
        return utils.ok(result=None, msg=f'LDAP object {ldap_id} deleted successfully.')


class OwnersResource(Resource):
    """
    Work with owner objects
    """

    def get(self):
        logger.debug(f"top of GET /owners")
        owners = TenantOwner.query.all()
        return utils.ok(result=[o.serialize for o in owners], msg="Owners retrieved successfully.")

    def post(self):
        logger.debug(f"top of POST /owners")
        validator = RequestValidator(utils.spec)
        result = validator.validate(FlaskOpenAPIRequest(request))
        if result.errors:
            raise errors.ResourceError(msg=f'Invalid POST data: {result.errors}.')
        validated_params = result.parameters
        validated_body = result.body
        owner = TenantOwner(name=validated_body.name,
                            email=validated_body.email,
                            institution=validated_body.institution,
                            create_time=datetime.datetime.utcnow(),
                            last_update_time=datetime.datetime.utcnow()
                            )
        db.session.add(owner)
        try:
            db.session.commit()
        except (sqlalchemy.exc.SQLAlchemyError, sqlalchemy.exc.DBAPIError) as e:
            msg = utils.get_message_from_sql_exc(e)
            raise errors.ResourceError(f"Invalid POST data; {msg}")
        return utils.ok(result=owner.serialize,
                        msg="Owner object created successfully.")


class OwnerResource(Resource):
    """
    Work with a single Owner object.
    """

    def get(self, email):
        logger.debug(f"top of GET /owners/{email}")
        owner = TenantOwner.query.filter_by(email=email).first()
        if not owner:
            raise errors.ResourceError(msg=f'No owner object found with email {email}.')
        return utils.ok(result=owner.serialize, msg='Owner object retrieved successfully.')

    def delete(self, email):
        logger.debug(f"top of DELETE /owners/{email}")
        owner = TenantOwner.query.filter_by(email=email).first()
        if not owner:
            raise errors.ResourceError(msg=f'No owner object found with email {email}.')
        db.session.delete(owner)
        db.session.commit()
        return utils.ok(result=None, msg=f'Owner object {owner} deleted successfully.')


class TenantsResource(Resource):
    """
    Work with tenants.
    """

    def get(self):
        logger.debug(f"top of GET /tenants")
        tenants = Tenant.query.all()
        return utils.ok(result=[t.serialize for t in tenants], msg="Tenants retrieved successfully.")

    def post(self):
        logger.debug(f"top of POST /tenants")
        validator = RequestValidator(utils.spec)
        result = validator.validate(FlaskOpenAPIRequest(request))
        if result.errors:
            logger.debug(f"openapi_core validattion failed. errors: {result.errors}")
            raise errors.ResourceError(msg=f'Invalid POST data: {result.errors}.')
        logger.debug("initial openapi_core validation passed.")
        validated_params = result.parameters
        validated_body = result.body

        # check reserved words "owners" and "ldaps" -- these cannot be tenant id's:
        if validated_body.tenant_id.lower() == 'owners':
            raise errors.ResourceError("Invalid tenant_id; 'owners' is a reserved keyword.")
        if validated_body.tenant_id.lower() == 'ldaps':
            raise errors.ResourceError("Invalid tenant_id; 'ldaps' is a reserved keyword.")

        # validate the existence of the ldap and owner objects:
        owner = TenantOwner.query.filter_by(email=validated_body.owner).first()
        if not owner:
            raise errors.ResourceError(msg=f'Invalid tenant description. Owner {validated_body.owner} not found.')
        logger.debug("owner was valid.")

        # ldap objects are optional:
        if getattr(validated_body, 'user_ldap_connection_id', None):
            ldap = LDAPConnection.query.filter_by(ldap_id=validated_body.user_ldap_connection_id).first()
            if not ldap:
                raise errors.ResourceError(msg=f'Invalid tenant description. '
                                               f'LDAP {validated_body.user_ldap_connection_id} not found.')
        if getattr(validated_body, 'service_ldap_connection_id', None) and \
                not validated_body.service_ldap_connection_id == getattr(validated_body, 'user_ldap_connection_id', None):
            ldap = LDAPConnection.query.filter_by(ldap_id=validated_body.service_ldap_connection_id).first()
            if not ldap:
                raise errors.ResourceError(msg=f'Invalid tenant description. '
                                               f'LDAP {validated_body.service_ldap_connection_id} not found.')

        logger.debug("ldap was valid; creating tenant record..")
        # create the tenant record --
        tenant = Tenant(tenant_id=validated_body.tenant_id,
                        base_url=validated_body.base_url,
                        is_owned_by_associate_site=validated_body.is_owned_by_associate_site,
                        site_id=validated_body.site_id,
                        token_service=validated_body.token_service,
                        security_kernel=validated_body.security_kernel,
                        authenticator=validated_body.authenticator,
                        owner=validated_body.owner,
                        service_ldap_connection_id=getattr(validated_body, 'service_ldap_connection_id', None),
                        user_ldap_connection_id=getattr(validated_body, 'user_ldap_connection_id', None),
                        description=getattr(validated_body, 'description', None),
                        create_time=datetime.datetime.utcnow(),
                        last_update_time=datetime.datetime.utcnow())
        db.session.add(tenant)
        try:
            db.session.commit()
            logger.info(f"new tenant committed to db. tenant object: {tenant}")
        except (sqlalchemy.exc.SQLAlchemyError, sqlalchemy.exc.DBAPIError) as e:
            logger.debug(f"got exception trying to commit new tenant object to db. Exception: {e}")
            msg = utils.get_message_from_sql_exc(e)
            logger.debug(f"returning msg: {msg}")
            raise errors.ResourceError(f"Invalid POST data; {msg}")
        logger.debug("returning serialized tenant object.")
        return utils.ok(result=tenant.serialize, msg="Tenant created successfully.")


class TenantResource(Resource):
    """
    Work with a single Tenant object.
    """

    def get(self, tenant_id):
        logger.debug(f"top of GET /tenants/{tenant_id}")
        tenant = Tenant.query.filter_by(tenant_id=tenant_id).first()
        if not tenant:
            raise errors.ResourceError(msg=f'No tenant found with tenant_id {tenant_id}.')
        return utils.ok(result=tenant.serialize, msg='Tenant retrieved successfully.')

    def delete(self, tenant_id):
        logger.debug(f"top of DELETE /tenants/{tenant_id}")
        tenant = Tenant.query.filter_by(tenant_id=tenant_id).first()
        if not tenant:
            logger.debug(f"Did not find a tenant with id {tenant_id}. Returning an error.")
            raise errors.ResourceError(msg=f'No tenant found with tenant_id {tenant_id}.')
        logger.debug("tenant found; issuing delete and commit.")
        db.session.delete(tenant)
        db.session.commit()
        return utils.ok(result=None, msg=f'Tenant {tenant_id} deleted successfully.')
