from flask import g, request

from common import auth
from common.config import conf
from common import errors as common_errors
from tapy.dyna import DynaTapy

# get the logger instance -
from common.logs import get_logger
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
        auth.authentication()
    except common_errors.NoTokenError as e:
        logger.debug(f"Caught NoTokenError: {e}")
        g.no_token = True
        g.username = None
        g.tenant_id = None
        # for retrieval and informational methods, allow the request (with possibly limited information)
        if request.method == 'GET' or request.method == 'OPTIONS' or request.method == 'HEAD':
            return True
        raise e


# this role is stored in the security kernel
ROLE = 'tenant_creator'

# this is the Tapis client that tenants will use for interacting with other services, such as the security kernel.
t = auth.get_service_tapy_client()

def authorization():
    """
    Entry point for checking authorization for all requests to the authenticator.
    :return:
    """
    logger.debug("top of authorization()")
    if not conf.use_sk:
        logger.debug("not using SK; returning True")
        return True
    if request.method == 'GET' or request.method == 'OPTIONS' or request.method == 'HEAD':
        logger.debug("method was GET, OPTIONS or HEAD; returning True")
        return True
    # check to make sure the user has the necessary role. -the tenant to check in is based on the tenant being
    # "served" by this instance of the
    logger.debug(f"calling SK to check users assigned to role: {ROLE}")
    try:
        users = t.sk.getUsersWithRole(roleName=ROLE)
    except Exception as e:
        msg = f'Got an error calling the SK. Exception: {e}'
        logger.error(msg)
        raise common_errors.PermissionsError(msg=f'Could not verify permissions with the Security Kernel; additional info: {e}')
    logger.debug(f"got users: {users}; checking if {g.username} is in role.")
    if g.username not in users.names:
        logger.info(f"user {g.username} was not in role. raising permissions error.")
        raise common_errors.PermissionsError(msg='Not authorized to modify the registry of tenants.')

