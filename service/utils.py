import datetime
from flask import request
from flask_restful import Resource
from openapi_core.shortcuts import RequestValidator
from openapi_core.wrappers.flask import FlaskOpenAPIRequest
# import psycopg2
import sqlalchemy
from service import db
from common import utils, errors
from service.models import LDAPConnection, TenantOwner, Tenant, Site

# get the logger instance -
from common.logs import get_logger
logger = get_logger(__name__)


def check_if_primary(data):
    if data.primary and data.base_url is not None and data.tenant_base_url_template is not None:
        logger.debug('checking if primary')
        primary_site = Site.query.filter_by(primary=True).first()
        if primary_site:
            raise errors.ResourceError("A primary site already exists.")
        else:
            site = Site(site_id=data.site_id,
                        primary=data.primary,
                        base_url=data.base_url,
                        tenant_base_url_template=data.tenant_base_url_template,
                        site_master_tenant_id=data.site_master_tenant_id,
                        services=data.services)
    elif data.primary and data.base_url is None:
        logger.debug('checking if primary but no base url provided')
        raise errors.ResourceError(f"Invalid POST data")
    else:
        logger.debug(f'not primary, creating site {data.tenant_base_url_template}')
        site = Site(site_id=data.site_id,
                    primary=False,
                    tenant_base_url_template=data.tenant_base_url_template,
                    site_master_tenant_id=data.site_master_tenant_id,
                    services=data.services)