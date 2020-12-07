from common.config import conf
from common.utils import TapisApi, handle_error, flask_errors_dict
from common.resources import HelloResource, ReadyResource
from flask_migrate import Migrate
from service import app
from service.auth import authn_and_authz
from service.controllers import LDAPsResource, LDAPResource, OwnersResource, OwnerResource, TenantsResource, \
    TenantResource, SitesResource, SiteResource

# authentication and authorization ---
@app.before_request
def authnz_for_authenticator():
    authn_and_authz()


# flask restful API object ----
api = TapisApi(app, errors=flask_errors_dict)

# Set up error handling
api.handle_error = handle_error
api.handle_exception = handle_error
api.handle_user_exception = handle_error

# Health-checks
api.add_resource(ReadyResource, '/v3/tenants/ready')
api.add_resource(HelloResource, '/v3/tenants/hello')

# Site Resources
api.add_resource(SitesResource, '/v3/sites')
api.add_resource(SiteResource, '/v3/sites/<site_id>')



api.add_resource(LDAPsResource, '/v3/tenants/ldaps')
api.add_resource(LDAPResource, '/v3/tenants/ldaps/<ldap_id>')

api.add_resource(OwnersResource, '/v3/tenants/owners')
api.add_resource(OwnerResource, '/v3/tenants/owners/<email>')

api.add_resource(TenantsResource, '/v3/tenants')
api.add_resource(TenantResource, '/v3/tenants/<tenant_id>')

# make sure the dev tenant is in place
from service.models import ensure_admin_tenant_present, ensure_dev_tenant_present

# the dev tenant requires the presence of the admin tenant.
if conf.ensure_dev_tenant:
    ensure_admin_tenant_present()
    ensure_dev_tenant_present()
elif conf.ensure_admin_tenant:
    ensure_admin_tenant_present()


# start the development server
if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
