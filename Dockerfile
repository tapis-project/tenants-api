# image: tapis/tenants-api
from tapis/flaskbase

COPY configschema.json /home/tapis/configschema.json
COPY config-local.json /home/tapis/config.json

COPY service /home/tapis/service

RUN chown -R tapis:tapis /home/tapis
USER tapis
