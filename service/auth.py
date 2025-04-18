from flask import g, request

from tapisservice import auth
from tapisservice.tapisflask import auth as flaskauth

from tapisservice.config import conf
from tapisservice.tenants import tenant_cache
from tapisservice import errors as common_errors

from service.models import get_sites, get_tenants

# get the logger instance -
from tapisservice.logs import get_logger
logger = get_logger(__name__)


def authn_and_authz():
    """
    Entry point for checking authentication and authorization for all requests to the authenticator.
    :return:
    """
    authentication()
    authorization()

def authentication():
    """
    Entry point for checking authentication for all requests to the authenticator.
    :return:
    """
    # The tenants API has both public endpoints that do not require a token as well as endpoints that require
    # authorization.
    # we always try to call the primary tapis authentication function to add authentication information to the
    # thread-local. If it fails due to a missing token, we then check if there is a p
    logger.debug("top of authentication()")
    try:
        flaskauth.authentication()
    except common_errors.NoTokenError as e:
        logger.debug(f"Caught NoTokenError: {e}")
        g.no_token = True
        g.username = None
        g.tenant_id = None
        # for retrieval and informational methods, allow the request (with possibly limited information)
        if request.method == 'GET' or request.method == 'OPTIONS' or request.method == 'HEAD':
            return True
        raise e


# these roles are stored in the security kernel --
ROLE = 'tenant_creator'

UPDATER_ROLE = 'tenant_definition_updater'

# this is the Tapis client that tenants will use for interacting with other services, such as the security kernel.
# we set a 'dummy' jwt because it is possible the Tokens API is not ready yet, or that the SK is not ready yet (tokens
# will validate the service password with SK). We do not want this to break the Tenants initialization; instead,
# we check for a 'dummy' JWT later, when checking authorization of a state-changing request to Tenants, and only
# then do we attempt to get a token.

# the tenants api always runs at the primary site; therefore, we can determine this service's tenant_id -- it is the
# admin tenant id for the primary site.
sites = get_sites()
tenants = get_tenants()
logger.info(f"Sites: {sites}")
logger.info(f"Tenants: {tenants}")
primary_site_admin_tenant_id = None
for s in sites:
    if s.get('primary'):
        primary_site_admin_tenant_id = s.get('site_admin_tenant_id')
        logger.debug(f"found prinary site; site_id: {s.get('site_id')}; admin tenant_id: {primary_site_admin_tenant_id}")
if primary_site_admin_tenant_id:
    t = auth.get_service_tapis_client(tenant_id=primary_site_admin_tenant_id, tenants=tenant_cache)
else:
    t = None
    logger.info(f'Could not find tenant_id for the primary site and was therefore not able to generate the tapis client.'
                f' This better be migrations...')


def authorization():
    """
    Entry point for checking authorization for all requests to the tenants API.
    :return:
    """
    logger.debug("top of authorization()")
    if not conf.use_sk:
        logger.debug("not using SK; returning True")
        return True
    if request.method == 'GET' or request.method == 'OPTIONS' or request.method == 'HEAD':
        logger.debug("method was GET, OPTIONS or HEAD; returning True")
        return True
    logger.debug(f"using SK; checking authorization. g.tenant_id: {g.tenant_id}; g.username: {g.username}")

    # all other actions require us to check roles with the SK, so we need a valid JWT
    get_tokens_on_tapipy_client()

    if request.method == 'PUT':
        # we first check for the tenant updater role --
        # note that g.tenant_id is the tenant_id claim of the X-Tapis-Token; i.e., it is the tenant that the
        # caller is in. Note that this could be a different tenant from the tenant the request is trying to
        # update; we will check that later.
        try:
            users = t.sk.getUsersWithRole(roleName=UPDATER_ROLE, tenant=g.tenant_id)
        except Exception as e:
            msg = f'Got an error calling the SK. Exception: {e}'
            logger.error(msg)
            # allow tenants API to make updates
            if g.username == 'tenants' and g.tenant_id == 'admin':
                logger.info("this is the tenants API; allowing the request even though role not found.")
                return True
            raise common_errors.PermissionsError(
                msg=f'Could not verify permissions with the Security Kernel; additional info: {e}')
        logger.debug(f"got users: {users}; checking if {g.username} is in UPDATER_ROLE.")
        if g.username not in users.names:
            logger.debug("user did not have UPDATER_ROLE")
            # allow tenants API to make updates
            if g.username == 'tenants' and g.tenant_id == 'admin':
                logger.info("this is the tenants API; allowing the request even though role not found.")
                return True
            raise common_errors.PermissionsError(msg='Not authorized to update this tenant.')

        # if the request is to update a specific tenant, we make the necessary checks in the controller based on the
        # tenant_id in the request.
        return True

    # otherwise, this is a request to create a tenant.
    # currently, only services in the admin tenant are allowed to create tenants.
    if not g.tenant_id == 'admin':
        raise common_errors.PermissionsError(msg='Permission denied; only services in the admin tenant can create '
                                                 'tenants.')
    # check that the service account is in the TENANT_CREATOR role
    logger.debug(f"calling SK to check users assigned to role: {ROLE}")
    try:
        users = t.sk.getUsersWithRole(roleName=ROLE, tenant=g.tenant_id)
    except Exception as e:
        msg = f'Got an error calling the SK. Exception: {e}'
        logger.error(msg)
        raise common_errors.PermissionsError(msg=f'Could not verify permissions with the Security Kernel; additional info: {e}')
    logger.debug(f"got users: {users}; checking if {g.username} is in role.")
    if g.username not in users.names:
        logger.info(f"user {g.username} was not in role. raising permissions error.")
        raise common_errors.PermissionsError(msg='Not authorized to modify the registry of tenants.')


def get_tokens_on_tapipy_client():
    """
    The Tenants API's tapipy client is initially constructed without a service token. This is because the Tenants API
    starts up before the Tokens API does, as it is required for the Tokens API startup; however, eventually the Tenants
    API will require a JWT to perform actions such as checking roles in SK. This function tries to add them if the
    jwt attribute is still "dummy".

    Note: this function will only succeed if Tokens and SK are both up already.
    """

    # the jwt attribute is created at initialization with a value of "dummy" -- so if it is still set to "dummy", we
    # need to generate tokens.
    if t.jwt == 'dummy':
        # try to replace with a real token:
        t.jwt = None
        try:
            t.get_tokens()
            logger.info("tenants-api has just called get_tokens().")
        except Exception as e:
            logger.info(f"Tenants could not retrieve a service token from the Tokens API; exception: {e}")
            logger.info(f"attrs on g: {dir(g)}")
            t.jwt = None
            raise common_errors.PermissionsError(msg=f'Could not retrieve service token from  the Tokens API. '
                                                     f'Tapis may still be initializing? Try request later.')
    # check to make sure the user has the necessary role. -the tenant to check in is based on the tenant being


def check_authz_tenant_update(tenant_id):
    """
    Called from the PUT controller and checks that one of the following are true on tenant update:
      1). the JWT's tenant_id claim matches the tenant_id being updated. OR
      2). the JWT's tenant_id claim is for the admin tenant for the site owning the tenant_id being updated.
    """
    # get the config for the tenant being updated, and in particular, get the owning site.
    logger.debug(f"top of check_authz_tenant_update for: {tenant_id}")
    # first we check if this is the tenants service at the primary site -- they are always allowed to make changes:
    if g.username == 'tenants' and g.tenant_id == 'admin':
        logger.info("this is the tenants API; allowing the request and not checking site and tenant details...")
        return True

    request_tenant = t.tenant_cache.get_tenant_config(tenant_id=tenant_id)
    site_id_for_request = request_tenant.site_id
    logger.debug(f"request_tenant: {request_tenant}; site_id_for_request: {site_id_for_request}")
    # if the tenant_id of the access token matched the tenant_id the request is trying to update, the request is
    # authorized
    if g.tenant_id == tenant_id:
        logger.debug(f"token's tenant {g.tenant_id} matched. request authorized.")
        return True
    # the second check is only for service tokens; if token was a user token, the request is not authorized:
    if not g.account_type == 'service':
        logger.info(f"the request was for a different tenant {tenant_id} than the token's tenant_id ({g.tenant_id}) and"
                    f"the token was not s service token. the request is not authorized.")
        raise common_errors.AuthenticationError(msg=f'Invalid tenant_id ({tenant_id}) provided. The token provided '
                                                    f'belongs to the {g.tenant_id} tenant but the request is trying to'
                                                    f'update the {tenant_id} tenant. Only service accounts can update'
                                                    f'other tenants.')
    # if the token tenant_id did not match the tenant_id in the request, the only way the request will be authorized is
    # if the token tenant_id is for the admin tenant of the owning site
    # to check this, get the site associated with the token:
    token_tenant = t.tenant_cache.get_tenant_config(tenant_id=g.tenant_id)
    site_id_for_token = token_tenant.site_id
    logger.debug(f"site_id_for_token: {site_id_for_token}")
    if site_id_for_request == site_id_for_token:
        logger.debug(f"token's site {site_id_for_token} matched tenant's site. request authorized.")
        return True
    logger.info(f"token site {site_id_for_token} did NOT match tenant's site ({site_id_for_request})")
    raise common_errors.AuthenticationError(msg=f'Invalid tenant_id ({tenant_id}) provided. This tenant belongs to'
                                                f'site {site_id_for_request} but the Tapis token passed in the'
                                                f'X-Tapis-Token header is for site {site_id_for_token}. Services'
                                                f'can only update tenants at their site.')



# utility methods --

def create_tenant_role():
    """
    Creates the tenant_creator role in the SK. This function only needs to run once per Tapis installation.
    :return: None
    """
    try:
        t.sk.createRole(roleName=ROLE, roleTenant='admin', description='Role controlling ability to create tenants.')
    except Exception as e:
        err = e


def grant_tenant_role(username, tenant_id):
    """
    Grant the tenant_creator role to username in tenant_id.
    :param tenant_id: 
    :param username: 
    :return: 
    """
    # TODO -- needs to be tested...
    t.sk.grantRole(userName=username, role=ROLE, tenant=tenant_id)

