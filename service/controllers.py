
from flask import request
from flask_restful import Resource
from openapi_core.shortcuts import RequestValidator
from openapi_core.wrappers.flask import FlaskOpenAPIRequest

from common import utils, errors
from service.models import db, LDAPConnection, TenantOwner, Tenant


class LDAPsResource(Resource):
    """
    Work with LDAP connection objects
    """

    # @swag_from("resources/ldaps/list.yml")
    def get(self):
        ldaps = LDAPConnection.query.all()
        return utils.ok(result=[l.serialize for l in ldaps], msg="LDAPs retrieved successfully.")

    def post(self):
        validator = RequestValidator(utils.spec)
        result = validator.validate(FlaskOpenAPIRequest(request))
        if result.errors:
            raise errors.ResourceError(msg=f'Invalid POST data: {result.errors}.')
        validated_params = result.parameters
        validated_body = result.body
        ldap = LDAPConnection(ldap_id=validated_body.ldap_id,
                              url=validated_body.url,
                              user_dn=validated_body.user_dn,
                              bind_dn=validated_body.bind_dn,
                              bind_credential=validated_body.bind_credential,
                              account_type=validated_body.account_type)
        db.session.add(ldap)
        db.session.commit()
        return utils.ok(result=ldap.serialize,
                        msg="LDAP object created successfully.")


class LDAPResource(Resource):
    """
    Work with a single LDAP connection object.
    """

    def get(self, ldap_id):
        ldap = LDAPConnection.query.filter_by(ldap_id=ldap_id).first()
        if not ldap:
            raise errors.ResourceError(msg=f'No LDAP object found with id {ldap_id}.')
        return utils.ok(result=ldap.serialize, msg='LDAP object retrieved successfully.')

    def delete(self, ldap_id):
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
        owners = TenantOwner.query.all()
        return utils.ok(result=[o.serialize for o in owners], msg="Owners retrieved successfully.")

    def post(self):
        validator = RequestValidator(utils.spec)
        result = validator.validate(FlaskOpenAPIRequest(request))
        if result.errors:
            raise errors.ResourceError(msg=f'Invalid POST data: {result.errors}.')
        validated_params = result.parameters
        validated_body = result.body
        owner = TenantOwner(name=validated_body.name,
                            email=validated_body.email,
                            institution=validated_body.institution)
        db.session.add(owner)
        db.session.commit()
        return utils.ok(result=owner.serialize,
                        msg="Owner object created successfully.")


class OwnerResource(Resource):
    """
    Work with a single Owner object.
    """

    def get(self, email):
        owner = TenantOwner.query.filter_by(email=email).first()
        if not owner:
            raise errors.ResourceError(msg=f'No owner object found with email {email}.')
        return utils.ok(result=owner.serialize, msg='Owner object retrieved successfully.')

    def delete(self, email):
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
        tenants = Tenant.query.all()
        return utils.ok(result=[t.serialize for t in tenants], msg="Tenants retrieved successfully.")

    def post(self):
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
                       token_service=validated_body.token_service,
                       security_kernel=validated_body.security_kernel,
                       owner=validated_body.owner,
                       service_ldap_connection_id=validated_body.service_ldap_connection_id,
                       user_ldap_connection_id=validated_body.user_ldap_connection_id,
                       description=validated_body.description)
        db.session.add(tenant)
        db.session.commit()
        return utils.ok(result=tenant.serialize, msg="Tenant created successfully.")


class TenantResource(Resource):
    """
    Work with a single Tenant object.
    """

    def get(self, tenant_id):
        tenant = Tenant.query.filter_by(tenant_id=tenant_id).first()
        if not tenant_id:
            raise errors.ResourceError(msg=f'No tenant found with tenant_id {tenant_id}.')
        return utils.ok(result=tenant.serialize, msg='Tenant retrieved successfully.')

    def delete(self, tenant_id):
        tenant = Tenant.query.filter_by(tenant_id=tenant_id).first()
        if not tenant:
            raise errors.ResourceError(msg=f'No tenant found with tenant_id {tenant_id}.')
        db.session.delete(tenant)
        db.session.commit()
        return utils.ok(result=None, msg=f'Tenant {tenant} deleted successfully.')

