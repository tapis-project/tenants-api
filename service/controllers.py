import datetime
from flask import request
from flask_restful import Resource
from openapi_core.shortcuts import RequestValidator
from openapi_core.wrappers.flask import FlaskOpenAPIRequest
# import psycopg2
import sqlalchemy

from common import utils, errors
from service.models import db, LDAPConnection, TenantOwner, Tenant

# get the logger instance -
from common.logs import get_logger
logger = get_logger(__name__)


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
        db.session.delete(ldap)
        db.session.commit()
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
            raise errors.ResourceError(msg=f'Invalid POST data: {result.errors}.')
        validated_params = result.parameters
        validated_body = result.body
        # validate the existence of the ldap and owner objects:
        owner = TenantOwner.query.filter_by(email=validated_body.owner).first()
        if not owner:
            raise errors.ResourceError(msg=f'Invalid tenant description. Owner {validated_body.owner} not found.')
        # ldap objects are optional:
        if validated_body.user_ldap_connection_id:
            ldap = LDAPConnection.query.filter_by(ldap_id=validated_body.user_ldap_connection_id).first()
            if not ldap:
                raise errors.ResourceError(msg=f'Invalid tenant description. '
                                               f'LDAP {validated_body.user_ldap_connection_id} not found.')
        if validated_body.service_ldap_connection_id and \
                not validated_body.service_ldap_connection_id == validated_body.user_ldap_connection_id:
            ldap = LDAPConnection.query.filter_by(ldap_id=validated_body.service_ldap_connection_id).first()
            if not ldap:
                raise errors.ResourceError(msg=f'Invalid tenant description. '
                                               f'LDAP {validated_body.service_ldap_connection_id} not found.')
        # create the tenant record --
        tenant = Tenant(tenant_id=validated_body.tenant_id,
                        base_url=validated_body.base_url,
                        is_owned_by_associate_site=validated_body.is_owned_by_associate_site,
                        token_service=validated_body.token_service,
                        security_kernel=validated_body.security_kernel,
                        authenticator=validated_body.authenticator,
                        owner=validated_body.owner,
                        service_ldap_connection_id=validated_body.service_ldap_connection_id,
                        user_ldap_connection_id=validated_body.user_ldap_connection_id,
                        description=validated_body.description,
                        create_time=datetime.datetime.utcnow(),
                        last_update_time=datetime.datetime.utcnow())
        db.session.add(tenant)
        try:
            db.session.commit()
        except (sqlalchemy.exc.SQLAlchemyError, sqlalchemy.exc.DBAPIError) as e:
            msg = utils.get_message_from_sql_exc(e)
            raise errors.ResourceError(f"Invalid POST data; {msg}")
        return utils.ok(result=tenant.serialize, msg="Tenant created successfully.")


class TenantResource(Resource):
    """
    Work with a single Tenant object.
    """

    def get(self, tenant_id):
        logger.debug(f"top of GET /tenants/{tenant_id}")
        tenant = Tenant.query.filter_by(tenant_id=tenant_id).first()
        if not tenant_id:
            raise errors.ResourceError(msg=f'No tenant found with tenant_id {tenant_id}.')
        return utils.ok(result=tenant.serialize, msg='Tenant retrieved successfully.')

    def delete(self, tenant_id):
        logger.debug(f"top of DELETE /tenants/{tenant_id}")
        tenant = Tenant.query.filter_by(tenant_id=tenant_id).first()
        if not tenant:
            raise errors.ResourceError(msg=f'No tenant found with tenant_id {tenant_id}.')
        db.session.delete(tenant)
        db.session.commit()
        return utils.ok(result=None, msg=f'Tenant {tenant} deleted successfully.')

