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
    if not conf.use_sk:
        return True
    if request.method == 'GET' or request.method == 'OPTIONS' or request.method == 'HEAD':
        return True
    # check to make sure the user has the necessary role. -the tenant to check in is based on the tenant being
    # "served" by this instance of the
    users = t.sk.getUsersWithRole(roleName=ROLE)
    if g.username not in users.names:
        raise common_errors.PermissionsError(msg='Not authorized to modify the registry of tenants.')

