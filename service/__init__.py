from common.config import conf
from flask import Flask
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = conf.sql_db_url
db = SQLAlchemy(app)
migrate = Migrate(app, db)