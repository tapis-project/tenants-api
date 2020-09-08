# Tapis Tenants API

REST API for managing tenants associated with a Tapis instance.


## Usage
This repository includes build files and other assets needed to start the service locally. Clone this
repository and follow the steps in the subsequent section.

### Start the API Locally
We are automating the management of the lifecycle workflow with `make`. You will need to install `make` it in order
to use the steps bellow.

The make system is generic and used by multiple Tapis services. Before following any of the sections below,
be sure to

```
$ export API_NAME=tenants
```

The `API_NAME` variable is used to let the `make` system know which Tapis service to work with.


#### First Time Setup
Starting the API the first time requires some initial setup. Do the following steps once per machine:

1. `make init_dbs` - creates a new docker volume, `tenant-api_pgdata`, creates a new Postrgres
Docker container with the volume created, and creates the initial (empty) database and database user.
2. `make migrate.upgrade` - runs the migrations contained within the `migrations/versions` directory.
3. `docker-compose up -d tenants` - starts the Tenats API.

#### Updating the API After the First Setup
Once the First Time Setup has been done a machine, updates can be fetched applied as follows:

1. `git pull` - Download the latest updates locally.
2. `make build.api` - Build a new version of the API container image.
3. `make migrate.upgade` - Run any new migrations (this step is only needed if new files appear in the `versions`
directory).migrations
4. `docker-compose up -d tenants` - start a new version of the Tenats API.

#### New DB Schema
During initial development, the database schema can be in flux. Changes to the models require new migrations. Instead of
adding additional migration versions, the database and associated `migrations` directory can be "wiped" and recreated
from the new models code using the following steps:

1. `make wipe` - removes the database and API container, database volume, and the `migrations` directory.database
2. `make init_dbs` - creates a new docker volume, `tenant-api_pgdata`, creates a new Postrgres
Docker container with the volume created, and creates the initial (empty) database and database user.
3. Add the migrations:

```
docker run -it --rm --entrypoint=bash --network=tenants-api_tenants -v $(pwd):/home/tapis/mig tapis/tenants-api
  # inside the container:
  $ cd mig; flask db init
  $ flask db migrate
  $ flask db upgrade
  $ exit
```

### Quickstart
Use any HTTP client to interact with the running API. The following examples use `curl`.

There are three primary collections supported by this API - `/tenants`, `/tenants/owners`, and `/tenants/ldaps`.
Creating a tenant requires references to an owner object and (optionally) an LDAP object.

To illustrate, we will register the TACC production tenant. We first begin by creating an owner
for our tenant.

**Note**: Creating, modifying or deleting any of the objects requires a valid Tapis JWT. In the examples
below, we assume a valid JWT has been exported to the `jwt` variable.
  
#### Work With Owners
Owners have three fields, all required: `name`, `email`, and `institution`. We can create an 
owner like so:

```
$ curl -H "X-Tapis-Token: $jwt" localhost:5000/v3/tenants/owners -H "content-type: application/json" -d '{"name": "Joe Stubbs", "email": "jstubbs@tacc.utexas.edu", "institution": "UT Austin"}'

{
  "message": "Owner created successfully.",
  "result":
    {
      "email": "jstubbs@tacc.utexas.edu",
      "institution": "UT Austin",
      "name": "Joe Stubbs"
    },
  "status": "success",
  "version": "dev"
}

```
We can list the owners by making a `GET` request to `/owners`, and we can retrieve details about
an owner using the owner's email address; for example:

```
$ curl -H "X-Tapis-Token: $jwt" localhost:5000/v3/tenants/owners | jq
{
  "message": "Owners retrieved successfully.",
  "result": [
    {
      "email": "jstubbs@tacc.utexas.edu",
      "institution": "UT Austin",
      "name": "Joe Stubbs"
    }
  ],
  "status": "success",
  "version": "dev"
}

curl -H "X-Tapis-Token: $jwt" localhost:5000/v3/tenants/owners/jstubbs@tacc.utexas.edu | jq
{
  "message": "Owner object retrieved successfully.",
  "result": {
    "email": "jstubbs@tacc.utexas.edu",
    "institution": "UT Austin",
    "name": "Joe Stubbs"
  },
  "status": "success",
  "version": "dev"
}

```

#### Work With LDAP Objects

LDAP objects represent collections of accounts on remote LDAP servers, together with connection
information detailing how to bind to the LDAP. Two types of LDAP objects are supported: `user` and
`service`. These types correspond to the two types of accounts in any Tapis tenant.
 
LDAP objects also require a `bind_credential`. This is a reference to a credential that
is retrievable from the Tapis Security Kernel.

We will create two LDAP objects for the TACC tenant, one for user accounts and one for
service accounts. First we create the service account ldap:

```
$ curl -H "X-Tapis-Token: $jwt" localhost:5000/v3/tenants/ldaps -H "content-type: application/json" -d '{"url":"ldaps://tapisldap.tacc.utexas.edu", "port": 636, "use_ssl": true, "user_dn": "ou=tacc.prod.service,dc=tapisapi", "bind_dn": "cn=admin,dc=tapisapi", "bind_credential": "/tapis/tapis.prod.ldapbind", "account_type": "service", "ldap_id": "tacc.prod.service"}'
{
	"message": "LDAP object created successfully.",
	"result": {
		"account_type": "LDAPAccountTypes.service",
		"bind_credential": "/tapis/tapis.prod.ldapbind",
		"bind_dn": "cn=admin,dc=tapisapi",
		"ldap_id": "tacc.prod.service",
		"url": "ldaps://tapisldap.tacc.utexas.edu",
		"user_dn": "ou=tacc.prod.service,dc=tapisapi"
	},
	"status": "success",
	"version": "dev"
}

```

Next, the user accounts ldap:

```
$ curl -H "X-Tapis-Token: $jwt" localhost:5000/v3/tenants/ldaps -H "content-type: application/json" -d '{"url":"ldaps://ldap.tacc.utexas.edu", "port": 636, "use_ssl": true, "user_dn": "ou=People,dc=tacc,dc=utexas,dc=edu", "bind_dn": "uid=ldapbind,ou=People,dc=tacc,dc=utexas,dc=edu", "bind_credential": "/tapis/tacc.prod.ldapbind", "account_type": "user", "ldap_id": "tacc-all"}'
{
	"message": "LDAP object created successfully.",
	"result": {
		"account_type": "LDAPAccountTypes.user",
		"bind_credential": "/tapis/tacc.prod.ldapbind",
		"bind_dn": "uid=ldapbind,ou=People,dc=tacc,dc=utexas,dc=edu",
		"ldap_id": "tacc-all",
		"url": "ldaps://ldap.tacc.utexas.edu:636",
		"user_dn": "ou=People,dc=tacc,dc=utexas,dc=edu"
	},
	"status": "success",
	"version": "dev"
}

```

Just as with the `/owners` collection and we can list all LDAP objects and get details about
specific LDAP objects using the usual GET requests. For example,

```
$ curl -H "X-Tapis-Token: $jwt" localhost:5000/v3/tenants/ldaps/tacc-all | jq
{
  "message": "LDAP object retrieved successfully.",
  "result": {
    "account_type": "LDAPAccountTypes.user",
    "bind_credential": "/tapis/tacc.prod.ldapbind",
    "bind_dn": "uid=ldapbind,ou=People,dc=tacc,dc=utexas,dc=edu",
    "ldap_id": "tacc-all",
    "url": "ldaps://ldap.tacc.utexas.edu:636",
    "user_dn": "ou=People,dc=tacc,dc=utexas,dc=edu"
  },
  "status": "success",
  "version": "
```

#### Work With Tenants

Now that we have an owner and LDAP objects created, we are ready to create our TACC production
tenant.

```
$ curl -H "X-Tapis-Token: $jwt" localhost:5000/v3/tenants -H "content-type: application/json" -d '{"tenant_id":"tacc", "base_url": "https://api.tacc.utexas.edu", "token_service": "https://api.tacc.utexas.edu/v3/token", "security_kernel": "https://api.tacc.utexas.edu/v3/security", "owner": "jstubbs@tacc.utexas.edu", "service_ldap_connection_id": "tacc.prod.service", "user_ldap_connection_id": "tacc-all", "description": "Production tenant for all TACC users.", "is_owned_by_associate_site": true, "site_id": "tacc", "authenticator": "https://api.tacc.utexas.edu/v3/oauth2"}'

{
  "message": "Tenant created successfully.",
  "result": {
    "authenticator": "https://api.tacc.utexas.edu/oauth2/v3",
    "base_url": "https://api.tacc.utexas.edu",
    "create_time": "Mon, 04 Nov 2019 20:09:18 GMT",
    "description": "Production tenant for all TACC users.",
    "last_update_time": "Mon, 04 Nov 2019 20:09:18 GMT",
    "owner": "jstubbs@tacc.utexas.edu",
    "security_kernel": "https://api.tacc.utexas.edu/security/v3",
    "service_ldap_connection_id": "tacc.prod.service",
    "tenant_id": "tacc",
    "token_service": "https://api.tacc.utexas.edu/token/v3",
    "user_ldap_connection_id": "tacc-all"
  },
  "status": "success",
  "version": "dev"
}

```
Listing and retrieving tenants works just like in the case of owners and LDAP objects.


### Beyond the Quickstart

A complete OpenAPI v3 spec file is included in the `service/resources` directory within this repository.


## Development
Follow the instructions for starting the API locally. 

### Running the Tests
The tests require the database to be running with the migrations applied. 
Use the ``make test`` command to wipe all data in the local environment,
rebuild the images and volume, and run the tests.

Alternatively, ``make build`` followed by ``docker-compose run tenants-tests``
will run the tests on top of a pre-build database with migrations. 


Note that since the tests destroy the database structure, it is advised that one
run a ``make clean`` and re-initialize the database after running tests.  

When ``"use_sk": true`` inside the ``config-local.json``, the tests will also require:

 * A valid Tapis token representing a user with the ``tenant_creator` role.
 * The computer where the tests run must be on the TACC VPN.
 
In this case, the test suite will make use of the Security Kernel (sk) running
in the develop environment. 
 
## Adding the TACC Tenant in Develop

As an example of adding a "realistic" tenant, we show how to add the TACC tenant to the develop
instance:

```

# create the ldap:
curl -H "X-Tapis-Token: $jwt" https://dev.develop.tapis.io/v3/tenants/ldaps -H "content-type: application/json" -d '{"url":"ldaps://ldap.tacc.utexas.edu", "port": 636, "use_ssl": true, "user_dn": "ou=People,dc=tacc,dc=utexas,dc=edu", "bind_dn": "uid=ldapbind,ou=People,dc=tacc,dc=utexas,dc=edu", "bind_credential": "/tapis/tacc.prod.ldapbind", "account_type": "user", "ldap_id": "tacc-all"}'

# create the tenant
curl -H "X-Tapis-Token: $jwt" https://dev.develop.tapis.io/v3/tenants -H "content-type: application/json" -d '{"tenant_id":"tacc", "base_url": "https://tacc.develop.tapis.io", "token_service": "https://tacc.develop.tapis.io/v3/tokens", "security_kernel": "https://tacc.develop.tapis.io/v3/security", "owner": "jstubbs@tacc.utexas.edu", "user_ldap_connection_id": "tacc-all", "description": "Production tenant for all TACC users.", "is_owned_by_associate_site": true, "site_id": "tacc", "authenticator": "https://tacc.develop.tapis.io/v3/oauth2"}'
```