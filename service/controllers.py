import datetime
import json
from flask import request, g
from flask_restful import Resource
from openapi_core import openapi_request_validator
from openapi_core.contrib.flask import FlaskOpenAPIRequest
# import psycopg2
import sqlalchemy
from service import db
from service.auth import check_authz_tenant_update
from tapisservice import errors
from tapisservice.tapisflask import utils 
from service.models import LDAPConnection, TenantOwner, Tenant, TenantHistory, Site

# get the logger instance -
from tapisservice.logs import get_logger
logger = get_logger(__name__)


class SitesResource(Resource):

    def get(self):
        logger.debug("top of GET /sites")
        sites = Site.query.all()
        return utils.ok(result=[s.serialize for s in sites], msg="Sites retrieved successfully.")

    def post(self):
        logger.debug("top of POST /sites")
        result = openapi_request_validator.validate(utils.spec, FlaskOpenAPIRequest(request))
        logger.debug(f"just got result {result.parameters}")
        if result.errors:
            logger.debug(f"error in results!!!!!!!!")
            raise errors.ResourceError(msg=f'Invalid POST data: {result.errors}')
        validated_params = result.parameters
        logger.debug('got validated params')
        validated_body = result.body
        logger.debug(f'got validated body {dir(validated_body)}')
        try:
            # request is trying to create the primary site:
            if validated_body.primary:
                logger.debug('checks for primary site')
                primary_site = Site.query.filter_by(primary=True).first()
                if primary_site:
                    raise errors.ResourceError("Invalid site description: a primary site already exists.")
                if not validated_body.tenant_base_url_template:
                    raise errors.ResourceError("Invalid site description: tenant_base_url_template is required for primary site.")
                site = Site(site_id=validated_body.site_id,
                            primary=validated_body.primary,
                            base_url=validated_body.base_url,
                            tenant_base_url_template=validated_body.tenant_base_url_template,
                            site_admin_tenant_id=validated_body.site_admin_tenant_id,
                            services=validated_body.services,
                            create_time=datetime.datetime.utcnow(),
                            created_by=f'{g.username}@{g.tenant_id}',
                            last_updated_by=f'{g.username}@{g.tenant_id}',
                            last_update_time=datetime.datetime.utcnow())

            # request if for an associate site:
            else:
                logger.debug(f'checks for associate site.')
                if hasattr(validated_body, 'tenant_base_url_template') and validated_body.tenant_base_url_template:
                    raise errors.ResourceError("Invalid site description; "
                                               "the tenant_base_url_template property only applies to primary sites.")
                site = Site(site_id=validated_body.site_id,
                            primary=False,
                            base_url=validated_body.base_url,
                            site_admin_tenant_id=validated_body.site_admin_tenant_id,
                            services=validated_body.services,
                            create_time=datetime.datetime.utcnow(),
                            created_by=f'{g.username}@{g.tenant_id}',
                            last_updated_by=f'{g.username}@{g.tenant_id}',
                            last_update_time=datetime.datetime.utcnow())
            logger.info(f'creating site {validated_body.site_id}')
        except Exception as e:
            raise errors.ResourceError(f"Invalid POST data; {e}")
        db.session.add(site)
        try:
            db.session.commit()
        except (sqlalchemy.exc.SQLAlchemyError, sqlalchemy.exc.DBAPIError) as e:
            msg = utils.get_message_from_sql_exc(e)
            raise errors.ResourceError(f"Invalid POST data; {msg}")
        logger.info(f"site {validated_body.site_id} saved in db.")
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
        site = Site.query.filter_by(site_id=site_id).first()
        if not site:
            logger.debug(f"Did not find a site with id {site_id}. Returning an error.")
            raise errors.ResourceError(msg=f'No site found with site_id {site_id}.')
        logger.debug("site found; issuing delete and commit.")
        db.session.delete(site)
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
        result = openapi_request_validator.validate(utils.spec, FlaskOpenAPIRequest(request))
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
        result = openapi_request_validator.validate(utils.spec, FlaskOpenAPIRequest(request))
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
        show_draft = request.args.get('show_draft', False)
        show_inactive = request.args.get('show_inactive', False)
        logger.debug(request.args)
        logger.debug(f"show_draft: {show_draft}; show_inactive: {show_inactive}")
        # get select parameter for only returning certain fields
        select_str = request.args.get('select', '')
        # these are the fields that can be selected from the tenants model

        selected_fields = []
        # iterate through the comma-separated list of selected attributes provided by the user to determine which
        # are selectable.
        if select_str:
            select_list = select_str.split(',')
            for attribute in select_list:
                if attribute.strip() in Tenant.selectable_fields:
                    # create the argument to the with_entities() sqlalchemy function; this is a list of
                    # the form Tenant.<field>
                    selected_fields.append(getattr(Tenant, attribute.strip()))
        logger.debug(f"selected_fields: {selected_fields}")
        if show_draft and show_inactive:
            logger.debug("getting all")
            if len(selected_fields) > 0:
                tenants = [Tenant(**t) for t in Tenant.query.with_entities(*selected_fields).all()]
            else:
                tenants = Tenant.query.all()
        elif show_draft:
            logger.debug("getting active or draft")
            if len(selected_fields) > 0:
                tenants = [Tenant(**t) for t in db.session.query(Tenant).filter(
                    sqlalchemy.or_(Tenant.status == 'active', Tenant.status == 'draft')).with_entities(*selected_fields).all()]
            else:
                tenants = db.session.query(Tenant).filter(sqlalchemy.or_(Tenant.status=='active', Tenant.status=='draft')).all()
        elif show_inactive:
            logger.debug("getting active or inactive")
            if len(selected_fields) > 0:
                tenants = [Tenant(**t) for t in db.session.query(Tenant).filter(
                    sqlalchemy.or_(Tenant.status=='active', Tenant.status=='inactive')).with_entities(*selected_fields).all()]
            else:
                tenants = db.session.query(Tenant).filter(sqlalchemy.or_(Tenant.status == 'active', Tenant.status == 'inactive')).all()
        else:
            logger.debug("getting active")
            if len(selected_fields) > 0:
                tenants = [Tenant(**t) for t in db.session.query(Tenant).filter(Tenant.status=='active').with_entities(*selected_fields).all()]
            else:
                tenants = db.session.query(Tenant).filter(Tenant.status == 'active').all()
        return utils.ok(result=[t.serialize for t in tenants], msg="Tenants retrieved successfully.")

    def post(self):
        logger.debug(f"top of POST /tenants")
        result = openapi_request_validator.validate(utils.spec, FlaskOpenAPIRequest(request))
        if result.errors:
            logger.debug(f"openapi_core validation failed. errors: {result.errors}")
            raise errors.ResourceError(msg=f'Invalid POST data: {result.errors}.')

        validated_body = result.body
        logger.debug(f"initial openapi_core validation passed. validated_body: {dir(validated_body)}")

        # check reserved words "owners" and "ldaps" -- these cannot be tenant id's:
        try:
            if validated_body.tenant_id.lower() == 'owners':
                raise errors.ResourceError("Invalid tenant_id; 'owners' is a reserved keyword.")
            if validated_body.tenant_id.lower() == 'ldaps':
                raise errors.ResourceError("Invalid tenant_id; 'ldaps' is a reserved keyword.")
            if validated_body.tenant_id.lower() == 'ready':
                raise errors.ResourceError("Invalid tenant_id; 'ready' is a reserved keyword.")
            if validated_body.tenant_id.lower() == 'hello':
                raise errors.ResourceError("Invalid tenant_id; 'hello' is a reserved keyword.")
        except Exception as e:
            msg = f"Could not check tenant description for reserved words; Errors: {e}"
            logger.error(msg)
            raise errors.ResourceError(msg)
        logger.debug("got past the reserved words check.")
        # validate the existence of the site object:
        try:
            site_id = validated_body.site_id
            site = Site.query.filter_by(site_id=site_id).first()
        except Exception as e:
            logger.error(f"Got exception trying to retrieve site; e: {e}")
            raise errors.ResourceError(msg='Invalid tenant description; could not verify site_id.')
        if not site:
            raise errors.ResourceError(msg=f'Invalid tenant description. site {validated_body.site_id} not found.')
        logger.debug(f"site_id {site_id} is ok.")
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
                        site_id=validated_body.site_id,
                        status=validated_body.status,
                        public_key=getattr(validated_body, 'public_key', None),
                        token_service=validated_body.token_service,
                        security_kernel=validated_body.security_kernel,
                        authenticator=validated_body.authenticator,
                        owner=validated_body.owner,
                        admin_user=validated_body.admin_user,
                        token_gen_services=validated_body.token_gen_services,
                        service_ldap_connection_id=getattr(validated_body, 'service_ldap_connection_id', None),
                        user_ldap_connection_id=getattr(validated_body, 'user_ldap_connection_id', None),
                        description=getattr(validated_body, 'description', None),
                        create_time=datetime.datetime.utcnow(),
                        created_by=f'{g.username}@{g.tenant_id}',
                        last_updated_by=f'{g.username}@{g.tenant_id}',
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

    def put(self, tenant_id):
        logger.debug(f"top of PUT /tenants/{tenant_id}")
        tenant = Tenant.query.filter_by(tenant_id=tenant_id).first()
        if not tenant:
            raise errors.ResourceError(msg=f'No tenant found with tenant_id {tenant_id}.')
        # additional authorization checks on update based on the tenant_id of the request:
        check_authz_tenant_update(tenant_id)
        result = openapi_request_validator.validate(utils.spec, FlaskOpenAPIRequest(request))
        if result.errors:
            logger.debug(f"openapi_core validation failed. errors: {result.errors}")
            raise errors.ResourceError(msg=f'Invalid PUT data: {result.errors}.')
        validated_body = result.body
        logger.debug(f"initial openapi_core validation passed. validated_body: {dir(validated_body)}")
        # TODO --
        # ------------------------- This DOES NOT WORK ------------------------------------
        # the validated_body ONLY contains fields in the OAI spec; need to change this to look at the
        # request body itself
        if not getattr(validated_body, 'site_id', tenant.site_id) == tenant.site_id:
            raise errors.ResourceError(msg=f'Invalid PUT data: cannot change site_id.')
        if not getattr(validated_body, 'tenant_id', tenant.tenant_id) == tenant.tenant_id:
            raise errors.ResourceError(msg=f'Invalid PUT data: cannot change tenant_id.')
        if not getattr(validated_body, 'base_url', tenant.base_url) == tenant.base_url:
            raise errors.ResourceError(msg=f'Invalid PUT data: cannot change base_url.')
        # ------------------------------------------------------------------------------------

        # validate the existence of the ldap and owner objects:
        if getattr(validated_body, 'owner', None):
            owner = TenantOwner.query.filter_by(email=validated_body.owner).first()
            if not owner:
                raise errors.ResourceError(msg=f'Invalid tenant description. Owner {validated_body.owner} not found.')
            logger.debug("owner was valid.")
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

        # overlay the tenant_current with the updates specified in the request body.
        changes_dict = {}
        # security_kernel
        new_security_kernel = getattr(validated_body, 'security_kernel', None)
        if new_security_kernel and not new_security_kernel == tenant.security_kernel:
            changes_dict['security_kernel'] = {'prev': tenant.security_kernel, 'new': new_security_kernel}
            tenant.security_kernel = new_security_kernel
        # token_service
        new_tokens_service = getattr(validated_body, 'token_service', None)
        if new_tokens_service and not new_tokens_service == tenant.token_service:
            changes_dict['tokens_service'] = {'prev': tenant.token_service, 'new': new_tokens_service}
            tenant.token_service = new_tokens_service
        # authenticator
        new_authenticator = getattr(validated_body, 'authenticator', None)
        if new_authenticator and not new_authenticator == tenant.authenticator:
            changes_dict['authenticator'] = {'prev': tenant.authenticator, 'new': new_authenticator}
            tenant.authenticator = new_authenticator
        # admin_user
        new_admin_user = getattr(validated_body, 'admin_user', None)
        if new_admin_user and not new_admin_user == tenant.admin_user:
            changes_dict['admin_user'] = {'prev': tenant.admin_user, 'new': new_admin_user}
            tenant.admin_user = new_admin_user
        # token_gen_services
        new_token_gen_services = getattr(validated_body, 'token_gen_services', None)
        if new_token_gen_services and not new_token_gen_services == tenant.token_gen_services:
            changes_dict['token_gen_services'] = {'prev': tenant.token_gen_services, 'new': new_token_gen_services}
            tenant.token_gen_services = new_token_gen_services
        # service_ldap_connection_id
        new_service_ldap_connection_id = getattr(validated_body, 'service_ldap_connection_id', None)
        if new_service_ldap_connection_id and not new_service_ldap_connection_id == tenant.service_ldap_connection_id:
            changes_dict['service_ldap_connection_id'] = {'prev': tenant.service_ldap_connection_id,
                                                          'new': new_service_ldap_connection_id}
            tenant.service_ldap_connection_id = new_service_ldap_connection_id
        # user_ldap_connection_id
        new_user_ldap_connection_id = getattr(validated_body, 'user_ldap_connection_id', None)
        if new_user_ldap_connection_id and not new_user_ldap_connection_id == tenant.user_ldap_connection_id:
            changes_dict['user_ldap_connection_id'] = {'prev': tenant.user_ldap_connection_id,
                                                          'new': new_user_ldap_connection_id}
            tenant.user_ldap_connection_id = new_user_ldap_connection_id
        # public_key
        new_public_key = getattr(validated_body, 'public_key', None)
        if new_public_key and not new_public_key == tenant.public_key:
            changes_dict['public_key'] = {'prev': tenant.public_key, 'new': new_public_key}
            tenant.public_key = new_public_key
        # status
        new_status = getattr(validated_body, 'status', None)
        if new_status and not new_status == tenant.status:
            changes_dict['status'] = {'prev': tenant.status.serialize, 'new': new_status.upper()}
            tenant.status = new_status
        # description
        new_description = getattr(validated_body, 'description', None)
        if new_description and not new_description == tenant.description:
            changes_dict['description'] = {'prev': tenant.description, 'new': new_description}
            tenant.description = new_description
        # owner
        new_owner = getattr(validated_body, 'owner', None)
        if new_owner and not new_owner == tenant.owner:
            changes_dict['owner'] = {'prev': tenant.owner, 'new': new_owner}
            tenant.owner = new_owner
        # last_update_time and last_updated_by
        update_time = datetime.datetime.utcnow()
        updated_by = f'{g.username}@{g.tenant_id}'
        tenant.last_update_time = update_time
        tenant.last_updated_by = updated_by
        # create the history record
        tenant_history = TenantHistory(
            tenant_id=tenant.tenant_id,
            update_time=update_time,
            updated_by=updated_by,
            updates_as_json=json.dumps(changes_dict)
        )
        db.session.add(tenant_history)
        try:
            db.session.commit()
            logger.info(f"update to tenant committed to db. tenant object: {tenant}")
        except (sqlalchemy.exc.SQLAlchemyError, sqlalchemy.exc.DBAPIError) as e:
            logger.debug(f"got exception trying to commit updated tenant object to db. Exception: {e}")
            msg = utils.get_message_from_sql_exc(e)
            logger.debug(f"returning msg: {msg}")
            raise errors.ResourceError(f"Invalid PUT data; {msg}")
        logger.debug("returning serialized tenant object.")
        return utils.ok(result=tenant.serialize, msg="Tenant updated successfully.")

    def delete(self, tenant_id):
        logger.debug(f"top of DELETE /tenants/{tenant_id}")
        # updated jfs 5/2021 -- removed delete functionality, as deleting tenants can cause issues with
        # historical data that reference the tenant_id.
        raise errors.ResourceError(msg=f'Deleting tenants is not supported; '
                                       f'update the tenant status to inactive instead.')


class TenantHistoryResource(Resource):
    def get(self, tenant_id):
        logger.debug(f"top of GET /tenants/{tenant_id}/history")
        tenant = Tenant.query.filter_by(tenant_id=tenant_id).first()
        if not tenant:
            raise errors.ResourceError(msg=f'No tenant found with tenant_id {tenant_id}.')

        tenant_history_list = TenantHistory.query.filter_by(tenant_id=tenant_id).all()
        return utils.ok(result=[t.serialize for t in tenant_history_list], msg='Tenant history retrieved successfully.')
