from flaskbase.common import utils
from models import LDAPConnection

def list_ldaps(limit=None, offset=None):
    ldaps = LDAPConnection.query.all()
    return utils.ok(result=ldaps, msg="LDAPs retrieved successfully.")
