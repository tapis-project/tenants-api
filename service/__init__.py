from common.config import conf
from flask import Flask
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

# get the logger instance -
from common.logs import get_logger
logger = get_logger(__name__)


app = Flask(__name__)

try:
    full_db_url = f'postgres://{conf.postgres_user}:{conf.postgres_password}@{conf.sql_db_url}'
except Exception as e:
    logger.error(f"Got exception trying to build full_db_ulr; e: {e}")
    raise e

app.config['SQLALCHEMY_DATABASE_URI'] = full_db_url
db = SQLAlchemy(app)
migrate = Migrate(app, db)