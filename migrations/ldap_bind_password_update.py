# this script adds the correct bind_credential to exisiting ldap records; previous versions of the
# code did not add this field when adding these LDAPs.
from service.models import LDAPConnection
from service import db

# tacc-all
ldap = LDAPConnection.query.filter_by(ldap_id='tacc-all').first()
ldap.bind_credential = 'ldap.tacc-all'
db.session.commit()

# tapis-dev
ldap = LDAPConnection.query.filter_by(ldap_id='tapis-dev').first()
ldap.bind_credential = 'ldap.tapis-dev'
db.session.commit()
