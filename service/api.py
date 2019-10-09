from flask_migrate import Migrate

from common.utils import TapisApi, handle_error, flask_errors_dict

from service.controllers import LDAPsResource, LDAPResource, OwnersResource, OwnerResource, TenantsResource, \
    TenantResource
from service.models import db, app

# db and migrations ----
db.init_app(app)
migrate = Migrate(app, db)

# flask restful API object ----
api = TapisApi(app, errors=flask_errors_dict)

# Set up error handling
api.handle_error = handle_error
api.handle_exception = handle_error
api.handle_user_exception = handle_error

# Add resources
api.add_resource(LDAPsResource, '/ldaps')
api.add_resource(LDAPResource, '/ldaps/<ldap_id>')

api.add_resource(OwnersResource, '/owners')
api.add_resource(OwnerResource, '/owners/<email>')

api.add_resource(TenantsResource, '/tenants')
api.add_resource(TenantResource, '/tenants/<tenant_id>')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
