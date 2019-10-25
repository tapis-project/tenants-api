import pytest
import datetime
import json
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine


from service import models
from service.api import app
from common.config import conf

# engine = create_engine(conf.sql_db_url)
# Session = sessionmaker()

# @pytest.fixture(scope='module')
# def connection():
#     connection = engine.connect()
#     yield connection
#     connection.close()
#
#
# @pytest.fixture(scope='function')
# def session(connection):
#     transaction = connection.begin()
#     session = Session(bind=connection)
#     yield session
#     session.close()
#     transaction.rollback()

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
            id=1,
            ldap_id='tacc.test.serivce',
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
            id=2,
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
            id=1,
            tenant_id='test',
            base_url='https://api.tacc.utexas.edu',
            is_owned_by_associate_site=False,
            token_service='https://api.tacc.utexas.edu/token/v3',
            authenticator='test-authenticator',
            security_kernel='https://api.tacc.utexas.edu/security/v3',
            owner='jlooney@tacc.utexas.edu',
            service_ldap_connection_id='tacc.test.serivce',
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


def test_get(client, init_db):
    with client:
        response = client.get("http://localhost:5000/tenants")
        assert response.status_code == 200
