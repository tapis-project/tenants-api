import pytest
import datetime
import json

from service import models
from service.api import app
from common.config import conf


@pytest.fixture(scope='module')
def init_db():
    with app.app_context():
        models.db.drop_all()
        models.db.create_all()
        tenant_owner = models.TenantOwner(
            id='888',
            email='jlooney@tacc.utexas.edu',
            name='Looney',
            institution='TACC',
            create_time=datetime.datetime.now()
        )
        models.db.session.add(tenant_owner)
        models.db.session.commit()
        tenant_owner = models.TenantOwner(
            id='999',
            email='cicsupport@tacc.utexas.edu',
            name='CIC Support',
            institution='TACC',
            create_time=datetime.datetime.now()
        )
        models.db.session.add(tenant_owner)
        models.db.session.commit()

        tacc_site = models.Site(
            site_id='tacc',
            primary=False,
            base_url='tacc.utexas.edu',
            tenant_base_url_template='test',
            site_admin_tenant_id='test',
            services=['test']
        )
        models.db.session.add(tacc_site)
        models.db.session.commit()

        ldap_conn1 = models.LDAPConnection(
            id=111,
            ldap_id='tacc.test.service',
            url='ldaps://tapisldap.tacc.utexas.edu',
            port=636,
            use_ssl=False,
            user_dn='ou=tacc.prod.service,dc=tapisapi',
            bind_dn='uid=ldapbind,ou=People,dc=tacc,dc=utexas,dc=edu',
            bind_credential='/tapis/tacc.prod.ldapbind',
            account_type=models.LDAPAccountTypes.service,
            create_time=datetime.datetime.now()
        )
        models.db.session.add(ldap_conn1)
        models.db.session.commit()

        ldap_conn2 = models.LDAPConnection(
            id=999,
            ldap_id='tacc.test.user',
            url='ldaps://tapisldap.tacc.utexas.edu',
            port=636,
            use_ssl=False,
            user_dn='ou=tacc.prod.service,dc=tapisapi',
            bind_dn='uid=ldapbind,ou=People,dc=tacc,dc=utexas,dc=edu',
            bind_credential='/tapis/tacc.prod.ldapbind',
            account_type=models.LDAPAccountTypes.user,
            create_time=datetime.datetime.now()
        )
        models.db.session.add(ldap_conn2)
        models.db.session.commit()

        tenant = models.Tenant(
            id=888,
            tenant_id='dev',
            base_url='https://dev.develop.tapis.io',
            admin_user='jstubbs',
            token_gen_services=["test"],
            site_id='tacc',
            token_service='https://dev.develop.tapis.io/v3/tokens',
            authenticator='test-authenticator',
            security_kernel='https://dev.develop.tapis.io/v3/security',
            owner='jlooney@tacc.utexas.edu',
            service_ldap_connection_id='tacc.test.service',
            user_ldap_connection_id='tacc.test.user',
            description='testing',
            create_time=datetime.datetime.now()
        )
        models.db.session.add(tenant)
        models.db.session.commit()

        tenant = models.Tenant(
            id=999,
            tenant_id='admin',
            base_url='https://admin.develop.tapis.io',
            admin_user='jlooney',
            site_id='tacc',
            token_gen_services=['test'],
            token_service='https://admin.develop.tapis.io/v3/tokens',
            authenticator='test-authenticator',
            security_kernel='https://admin.develop.tapis.io/v3/security',
            owner='cicsupport@tacc.utexas.edu',
            description='testing',
            create_time=datetime.datetime.now()
        )
        models.db.session.add(tenant)
        models.db.session.commit()

        yield models.db
        models.db.session.close()
        models.db.drop_all()


@pytest.fixture
def client():
    app.debug = True
    return app.test_client()


### sites tests
def test_get_sites(client, init_db):
    with client:
        response = client.get("http://localhost:5000/v3/sites")
        assert response.status_code == 200


### tenants tests
def test_get_tenants(client, init_db):
    with client:
        response = client.get("http://localhost:5000/v3/tenants")
        assert response.status_code == 200


def test_add_tenant_with_post(client, init_db):
    with client:

        payload = {
            "id": 23498,
            "tenant_id":"tacc",
            "base_url": "https://test.tacc.utexas.edu",
            "token_service": "https://api.tacc.utexas.edu/token/v3",
            "security_kernel": "https://api.tacc.utexas.edu/security/v3",
            "owner": "jlooney@tacc.utexas.edu",
            "admin_user": "foobar",
            "token_gen_services": ["test"],
            "authenticator": "test",
            "site_id": "tacc",
            "service_ldap_connection_id": "tacc.test.service",
            "user_ldap_connection_id": "tacc.test.user",
            "description": "Test tenant for all TACC users."
        }
        headers = {
            "X-Tapis-Token": conf.test_jwt,
            "X-Tapis-Tenant": "admin",
            "X-Tapis-User": "tenants",
        }
        response = client.post(
            "http://localhost:5000/v3/tenants",
            headers=headers,
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 200


def test_add_tenant_without_optional_fields(client, init_db):
    with client:

        payload = {
            "id": 23498,
            "tenant_id": "test-dev",
            "admin_user": "foobar2",
            "base_url": "https://test-dev.develop.tapis.io",
            "token_service": "https://test-dev.develop.tapis.io/foo/token",
            "security_kernel": "https://test-dev.develop.tapis.io/bar/security",
            "owner": "jlooney@tacc.utexas.edu",
            "authenticator": "https://test-dev.develop.tapis.io/foobar/oauth",
            "site_id": "tacc",
            "token_gen_services": ["test"]
        }
        headers = {
            "X-Tapis-Token": conf.test_jwt,
            "X-Tapis-Tenant": "admin",
            "X-Tapis-User": "tenants",
        }
        response = client.post(
            "http://localhost:5000/v3/tenants",
            headers=headers,
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 200

def test_list_tenants(client, init_db):
    with client:
        response = client.get("http://localhost:5000/v3/tenants")
        assert response.status_code == 200
        result = response.json['result']
        print(f"list_tenants found {len(result)} tenants.")
        for tenant in result:
            assert 'tenant_id' in tenant
            assert 'base_url' in tenant
            assert 'public_key' in tenant
            assert 'owner' in tenant
            assert 'token_service' in tenant
            assert 'security_kernel' in tenant
            assert 'authenticator' in tenant
            assert 'site_id' in tenant


def test_get_single_tenant(client, init_db):
    with client:
        response = client.get("http://localhost:5000/v3/tenants/dev")
        assert response.status_code == 200


def test_delete_single_tenant(client, init_db):
    with client:

        # First, create a new tenant so we can delete it
        payload = {
            "id": 23498,
            "tenant_id": "lolidk",
            "admin_user": "lolidk",
            "base_url": "https://lolidk.develop.tapis.io",
            "token_service": "https://lolidk.develop.tapis.io/foo/token",
            "security_kernel": "https://lolidk.develop.tapis.io/bar/security",
            "owner": "jlooney@tacc.utexas.edu",
            "authenticator": "https://test-dev.develop.tapis.io/foobar/oauth",
            "site_id": "tacc",
            "token_gen_services": ["test"]
        }
        headers = {
            "X-Tapis-Token": conf.test_jwt,
            "X-Tapis-Tenant": "admin",
            "X-Tapis-User": "tenants",
        }
        response = client.post(
            "http://localhost:5000/v3/tenants",
            headers=headers,
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 200

        # Now, delete the tenant we just created
        headers = {
            "X-Tapis-Token": conf.test_jwt,
            "X-Tapis-Tenant": "admin",
            "X-Tapis-User": "tenants",
        }
        response = client.delete(
            "http://localhost:5000/v3/tenants/lolidk",
            headers=headers,
            content_type='application/json'
        )
        assert response.status_code == 200


### ldaps tests
def test_add_ldap_with_post(client, init_db):
    with client:
        payload = {
            'ldap_id': 'post-test',
            'url': 'ldaps://test.tacc.utexas.edu',
            'port': 636,
            'use_ssl': False,
            'user_dn': 'ou=tacc.test.service,dc=tapisapi',
            'bind_dn': 'uid=ldapbind,ou=People,dc=tacc,dc=utexas,dc=edu',
            'bind_credential': '/tapis/tacc.prod/ldapbind',
            'account_type': 'user'
        }

        headers = {
            "X-Tapis-Token": conf.test_jwt,
            "X-Tapis-Tenant": "admin",
            "X-Tapis-User": "tenants",
        }
        response = client.post(
            "http://localhost:5000/v3/tenants/ldaps",
            headers=headers,
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 200


def test_get_list_of_ldaps(client, init_db):
    with client:
        response = client.get("http://localhost:5000/v3/tenants")
        assert response.status_code == 200

def test_get_single_ldap(client, init_db):
    with client:
        response = client.get("http://localhost:5000/v3/tenants/ldaps/tacc.test.user")
        assert response.status_code == 200

# def test_delete_single_ldap(client, init_db):
#     with client:
#         headers = {
#             "X-Tapis-Token": conf.test_jwt
#         }
#
#         # first check which tenants we have =
#         response = client.get("http://localhost:5000/v3/tenants")
#         assert response.status_code == 200
#         result = response.json['result']
#         print(f"list_tenants found {len(result)} tenants.")
#         for tenant in result:
#             print(tenant['tenant_id'])
#
#         # First remove the tenants that have the ldap as a foreign key
#         response = client.delete(
#             "http://localhost:5000/v3/tenants/dev",
#             headers=headers,
#             content_type='application/json'
#         )
#
#         assert response.status_code == 200
#
#         response = client.delete(
#             "http://localhost:5000/v3/tenants/dev",
#             headers=headers,
#             content_type='application/json'
#         )
#
#         assert response.status_code == 200
#         # Now remove the ldap
#         response2 = client.delete(
#             "http://localhost:5000/v3/tenants/ldaps/tacc.test.user",
#             headers=headers,
#             content_type='application/json'
#         )
#
#         assert response2.status_code == 200


### owners tests


def test_add_owner_with_post(client, init_db):
    payload = {
        "email": "jstubbs@tacc.utexas.edu",
        "name": "Joe Stubbs",
        "institution": "TACC"
    }
    headers = {
        "X-Tapis-Token": conf.test_jwt,
        "X-Tapis-Tenant": "admin",
        "X-Tapis-User": "tenants",
    }
    response = client.post(
        "http://localhost:5000/v3/tenants/owners",
        headers=headers,
        data=json.dumps(payload),
        content_type='application/json'
    )
    assert response.status_code == 200

def test_get_list_of_owners(client, init_db):
    with client:
        response = client.get("http://localhost:5000/v3/tenants/owners")
        assert response.status_code == 200


def test_get_single_owner(client, init_db):
    with client:
        response = client.get("http://localhost:5000/v3/tenants/owners/jstubbs@tacc.utexas.edu")
        assert response.status_code == 200


def test_delete_single_owner(client, init_db):
    with client:

        headers = {
            "X-Tapis-Token": conf.test_jwt,
            "X-Tapis-Tenant": "admin",
            "X-Tapis-User": "tenants",
        }

        response = client.delete(
            "http://localhost:5000/v3/tenants/owners/jstubbs@tacc.utexas.edu",
            headers=headers,
            content_type='application/json'
        )
        assert response.status_code == 200


def test_create_nonprimary_site(client, init_db):
    with client:
        headers = {
            "X-Tapis-Token": conf.test_jwt,
            "X-Tapis-Tenant": "admin",
            "X-Tapis-User": "tenants",
        }

        payload = {
            "site_id": "testsite",
            "primary": False,
            "base_url": "test",
            "tenant_base_url": "test",
            "site_admin_tenant_id": 'dev',
            "services": ['test']
        }


        response = client.post(
            "http://localhost:5000/v3/sites",
            headers=headers,
            data=json.dumps(payload),
            content_type='application/json'
        )

        assert response.status_code == 200


def test_cannot_create_multiple_primary_sites(client, init_db):
    with client:
        headers = {
            "X-Tapis-Token": conf.test_jwt,
            "X-Tapis-Tenant": "admin",
            "X-Tapis-User": "tenants",
        }

        payload = {
            "site_id": "testsite2",
            "primary": True,
            "base_url": "test",
            "tenant_base_url": "test",
            "site_admin_tenant_id": 'dev',
            "services": ['test']
        }


        response = client.post(
            "http://localhost:5000/v3/sites",
            headers=headers,
            data=json.dumps(payload),
            content_type='application/json'
        )

        assert response.status_code != 200





