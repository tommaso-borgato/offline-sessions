## Securing an application deployed to WildFly with Bearer Token Authentication

This example is taken from [Bearer Token Support for the Elytron OIDC Client Subsystem](https://wildfly-security.github.io/wildfly-elytron/blog/bearer-only-support-openid-connect/);

This example demonstrates how to secure an application deployed to WildFly with Bearer Token
Authentication when using the Elytron OpenID Connect (OIDC) Client subsystem.

The OIDC configuration in this example is part of the deployments themselves. Alternatively,
this configuration could be specified via the `elytron-oidc-client` subsystem instead.
For more details, take a look at the [documentation](https://docs.wildfly.org/26.1/Admin_Guide.html#Elytron_OIDC_Client).


### Usage

#### Set up your Keycloak OpenID provider

Start Keycloak (see [Get started with Keycloak on Docker](https://www.keycloak.org/getting-started/getting-started-docker)):
```shell
podman run --rm -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:21.1.2 start-dev
```

Follow the steps in this [getting started guide](https://www.keycloak.org/getting-started/getting-started-docker)
to start Keycloak and create a realm called `demo-realm`.

Next, create a client called `backend-service`. 
If you're using Keycloak 19.0.0 or later, in the `Capability config`, be sure to:
* uncheck `Standard flow`
* uncheck `Direct access grants`

when no authentication flows are specified, this indicates that the client is a bearer only client). 
For older versions of Keycloak, change the `Access Type` to `bearer-only`.

Now, we're going to create a second client called `frontend-web-app`. 
If you're using Keycloak 19.0.0 or later, in the `Capability config`, turn on `Client authentication`. 
For older versions of Keycloak, change the `Access Type` to `confidential`.

For the `frontend-web-app` client, we also need to set the valid redirect URIs to `http://localhost:8100/frontend-web-app/*` and set the
`Web origins` to `+` to permit all origins of Valid Redirect URIs.

Now, click on `Realm roles` and create two roles, `user` and `admin`.

Create a user called `alice` and assign her the `user` and `admin` roles. 
Create a user called `bob` and assign him only the `user` role. 
Steps for assigning roles can be found in the [Keycloak documentation](https://www.keycloak.org/docs/latest/server_admin/#proc-assigning-role-mappings_server_administration_guide).

#### Deploy the service and the app that invokes the service to WildFly

First, we're going to start our WildFly instances:
* `server1` will host [backend-service](backend-service)
* `server2` will host [frontend-web-app](frontend-web-app)

We are specifying a port offset for both `server1` and `server2` since our Keycloak instance is already exposed on port 8080;

Start `server1`:

```shell
cd server1

export OIDC_PROVIDER_URL=http://0.0.0.0:8080
export OIDC_REALM=demo-realm
export OIDC_CLIENT_ID=backend-service

./bin/standalone.sh -Djboss.socket.binding.port-offset=10
```

Notice that [frontend-web-app](frontend-web-app)'s `oidc.json` file is used to specify the secret that should be used when communicating with the Keycloak OpenID provider.

From the Keycloak Admin Console, navigate to the `frontend-web-app` client that we created earlier, then click on `Credentials`, and copy
the value for the `Client secret`: env variable OIDC_CLIENT_SECRET will contain its value.

Start `server2`:

```shell
cd server2

export OIDC_PROVIDER_URL=http://0.0.0.0:8080
export OIDC_REALM=demo-realm
export OIDC_CLIENT_ID=frontend-web-app
export OIDC_CLIENT_SECRET=vlYkeN55ffvVjGH8ZfI0ocw7bcLdcCBI
export BACKEND_SERVICE_URL=http://localhost:8090/backend-service/

./bin/standalone.sh -Djboss.socket.binding.port-offset=20
```

Alternatively, you can start two WildFly instances manually and deploy using the plugin:

First deploy the service:

```shell
cd oidc-with-bearer/service
mvn wildfly:deploy -Dwildfly.port=10000
```

Then, deploy the OIDC app:

```shell
cd oidc-with-bearer/app
mvn wildfly:deploy -Dwildfly.port=10010
```

#### Access the app

We can access our application using http://localhost:8100/frontend-web-app/.

Try invoking the different endpoints without logging in. You'll only be able to successfully invoke
the `public` endpoint.

Now try logging in as `alice`. You'll be redirected to Keycloak to log in. Then try invoking
the different endpoints again. This time, you'll be able to successfully invoke all three endpoints
because `alice` has both `user` and `admin` roles.

Finally, try accessing the application again but this time, log in as `bob`. When you try invoking
the endpoints now, you'll see that you can only invoke the `public` and `secured` endpoints
since `bob` does not have the `admin` role.

### Some notes

#### how-to get access token manually

First, obtain a refresh token:

```shell
CLIENT_SECRET='vlYkeN55ffvVjGH8ZfI0ocw7bcLdcCBI'
OFFLINE_TOKEN=$(curl -d 'client_id=frontend-web-app' \
  -d "client_secret=$CLIENT_SECRET" \
  -d "username=alice" \
  -d "password=redhat" \
  -d "grant_type=password" \
  -d "scope=openid offline_access" \
  http://0.0.0.0:8080/realms/demo-realm/protocol/openid-connect/token | jq -r '.refresh_token')
echo $OFFLINE_TOKEN
```

Then, use the refresh token to obtain an access token:

```shell
ACCESS_TOKEN=$(curl \
  -d "client_id=frontend-web-app" \
  -d "client_secret=vlYkeN55ffvVjGH8ZfI0ocw7bcLdcCBI" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$OFFLINE_TOKEN" \
  http://0.0.0.0:8080/realms/demo-realm/protocol/openid-connect/token | jq -r '.access_token')
echo $ACCESS_TOKEN
```

Finally, use the access token to access you service:

```shell
curl http://localhost:8090/backend-service/secured \
   -H "Accept: application/json" \
   -H "Authorization: Bearer $ACCESS_TOKEN" | jq
   
curl http://localhost:8090/backend-service/admin \
   -H "Accept: application/json" \
   -H "Authorization: Bearer $ACCESS_TOKEN" | jq
```
