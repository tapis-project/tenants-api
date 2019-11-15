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
            is_owned_by_associate_site=False,
            allowable_x_tenant_ids=['test'],
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
        yield models.db
        models.db.session.close()
        models.db.drop_all()


@pytest.fixture
def client():
    app.debug = True
    return app.test_client()


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
            "is_owned_by_associate_site": False,
            "authenticator": "test",
            "allowable_x_tenant_ids": ["dev", "tacc"],
            "service_ldap_connection_id": "tacc.test.service",
            "user_ldap_connection_id": "tacc.test.user",
            "description": "Test tenant for all TACC users."
        }
        headers = {
            "X-Tapis-Token": conf.test_jwt
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
            "tenant_id":"test-dev",
            "base_url": "https://test-dev.develop.tapis.io",
            "token_service": "https://test-dev.develop.tapis.io/foo/token",
            "security_kernel": "https://test-dev.develop.tapis.io/bar/security",
            "owner": "jlooney@tacc.utexas.edu",
            "is_owned_by_associate_site": False,
            "authenticator": "https://test-dev.develop.tapis.io/foobar/oauth",
            "allowable_x_tenant_ids": ["test-dev"],
        }
        headers = {
            "X-Tapis-Token": conf.test_jwt
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
            assert 'allowable_x_tenant_ids' in tenant


def test_get_single_tenant(client, init_db):
    with client:
        response = client.get("http://localhost:5000/v3/tenants/dev")
        assert response.status_code == 200


def test_delete_single_tenant(client, init_db):
    with client:
        headers = {
            "X-Tapis-Token": conf.test_jwt
        }
        response = client.delete(
            "http://localhost:5000/v3/tenants/test-dev",
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
            "X-Tapis-Token": conf.test_jwt
        }
        response = client.post(
            "http://localhost:5000/v3/ldaps",
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
        response = client.get("http://localhost:5000/v3/ldaps/tacc.test.user")
        assert response.status_code == 200

def test_delete_single_ldap(client, init_db):
    with client:
        headers = {
            "X-Tapis-Token": conf.test_jwt
        }

        # first check which tenants we have =
        response = client.get("http://localhost:5000/v3/tenants")
        assert response.status_code == 200
        result = response.json['result']
        print(f"list_tenants found {len(result)} tenants.")
        for tenant in result:
            print(tenant['tenant_id'])

        # First remove the tenants that have the ldap as a foreign key
        response = client.delete(
            "http://localhost:5000/v3/tenants/dev",
            headers=headers,
            content_type='application/json'
        )

        assert response.status_code == 200

        response = client.delete(
            "http://localhost:5000/v3/tenants/tacc",
            headers=headers,
            content_type='application/json'
        )

        assert response.status_code == 200
        # Now remove the ldap
        response2 = client.delete(
            "http://localhost:5000/v3/ldaps/tacc.test.user",
            headers=headers,
            content_type='application/json'
        )

        assert response2.status_code == 200


### owners tests


def test_add_owner_with_post(client, init_db):
    payload = {
        "email": "jstubbs@tacc.utexas.edu",
        "name": "Joe Stubbs",
        "institution": "TACC"
    }
    headers = {
        "X-Tapis-Token": conf.test_jwt
    }
    response = client.post(
        "http://localhost:5000/v3/owners",
        headers=headers,
        data=json.dumps(payload),
        content_type='application/json'
    )
    assert response.status_code == 200

def test_get_list_of_owners(client, init_db):
    with client:
        response = client.get("http://localhost:5000/v3/owners")
        assert response.status_code == 200


def test_get_single_owner(client, init_db):
    with client:
        response = client.get("http://localhost:5000/v3/owners/jstubbs@tacc.utexas.edu")
        assert response.status_code == 200


def test_delete_single_owner(client, init_db):
    with client:

        headers = {
            "X-Tapis-Token": conf.test_jwt
        }

        response = client.delete(
            "http://localhost:5000/v3/owners/jstubbs@tacc.utexas.edu",
            headers=headers,
            content_type='application/json'
        )
        assert response.status_code == 200




