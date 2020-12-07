"""empty message

Revision ID: 91e4c38a7717
Revises: 
Create Date: 2020-12-07 19:54:01.482816

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '91e4c38a7717'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('ldap_connections',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('ldap_id', sa.String(length=50), nullable=False),
    sa.Column('url', sa.String(length=2000), nullable=False),
    sa.Column('port', sa.Integer(), nullable=False),
    sa.Column('use_ssl', sa.Boolean(), nullable=False),
    sa.Column('user_dn', sa.String(length=200), nullable=False),
    sa.Column('bind_dn', sa.String(length=200), nullable=False),
    sa.Column('bind_credential', sa.String(length=200), nullable=False),
    sa.Column('account_type', sa.Enum('user', 'service', name='ldapaccounttypes'), nullable=False),
    sa.Column('create_time', sa.DateTime(), nullable=False),
    sa.Column('last_update_time', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('ldap_id')
    )
    op.create_table('site',
    sa.Column('site_id', sa.String(), nullable=False),
    sa.Column('primary', sa.Boolean(), nullable=False),
    sa.Column('base_url', sa.String(), nullable=True),
    sa.Column('tenant_base_url_template', sa.String(), nullable=True),
    sa.Column('site_admin_tenant_id', sa.String(), nullable=False),
    sa.Column('services', sa.ARRAY(sa.String()), nullable=False),
    sa.PrimaryKeyConstraint('site_id'),
    sa.UniqueConstraint('base_url'),
    sa.UniqueConstraint('tenant_base_url_template')
    )
    op.create_table('tenantOwners',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('name', sa.String(length=80), nullable=False),
    sa.Column('institution', sa.String(length=80), nullable=False),
    sa.Column('create_time', sa.DateTime(), nullable=False),
    sa.Column('last_update_time', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    op.create_table('tenants',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('tenant_id', sa.String(length=50), nullable=False),
    sa.Column('base_url', sa.String(length=2000), nullable=False),
    sa.Column('site_id', sa.String(length=50), nullable=False),
    sa.Column('token_service', sa.String(length=2000), nullable=False),
    sa.Column('security_kernel', sa.String(length=2000), nullable=False),
    sa.Column('authenticator', sa.String(length=2000), nullable=False),
    sa.Column('owner', sa.String(length=120), nullable=False),
    sa.Column('admin_user', sa.String(length=120), nullable=False),
    sa.Column('token_gen_services', sa.ARRAY(sa.String()), nullable=False),
    sa.Column('create_time', sa.DateTime(), nullable=False),
    sa.Column('last_update_time', sa.DateTime(), nullable=False),
    sa.Column('service_ldap_connection_id', sa.String(length=50), nullable=True),
    sa.Column('user_ldap_connection_id', sa.String(length=50), nullable=True),
    sa.Column('description', sa.String(length=1000), nullable=True),
    sa.ForeignKeyConstraint(['owner'], ['tenantOwners.email'], ),
    sa.ForeignKeyConstraint(['service_ldap_connection_id'], ['ldap_connections.ldap_id'], ),
    sa.ForeignKeyConstraint(['user_ldap_connection_id'], ['ldap_connections.ldap_id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('base_url'),
    sa.UniqueConstraint('tenant_id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('tenants')
    op.drop_table('tenantOwners')
    op.drop_table('site')
    op.drop_table('ldap_connections')
    # ### end Alembic commands ###
