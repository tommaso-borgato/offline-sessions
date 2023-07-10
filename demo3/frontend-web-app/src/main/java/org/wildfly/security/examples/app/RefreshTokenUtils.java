package org.wildfly.security.examples.app;

import jakarta.json.bind.Jsonb;
import jakarta.json.bind.JsonbBuilder;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRequest;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.Response;
import org.apache.commons.io.IOUtils;
import org.apache.http.conn.ssl.NoopHostnameVerifier;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.logging.Logger;

public class RefreshTokenUtils {


	private static final String DEFAULT_OIDC_PROVIDER_URL = "http://0.0.0.0:8080";

	static final CallbackHandler HANDLER = new CallbackHandler() {

		@Override
		public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
			throw new UnsupportedCallbackException(callbacks[0]);
		}
	};

	private static final Logger LOG = Logger.getLogger(RefreshTokenUtils.class.getName());
	private static final String FILE = System.getProperty("java.io.tmpdir") + "/" +
			(System.getenv("OIDC_CLIENT_ID") == null ? "frontend-web-app" : System.getenv("OIDC_CLIENT_ID"));


	protected static void saveToken(final String token) throws IOException {
		PrintWriter writer = null;
		try {
			LOG.info(String.format("Storing token %s in file %s", token, FILE));
			writer = new PrintWriter(new BufferedWriter(new FileWriter(FILE)));
			writer.print(token);
		} finally {
			if (writer != null) {
				writer.close();
			}
		}
	}

	protected static String loadToken() throws IOException {
		FileInputStream fis = null;
		try {
			LOG.info(String.format("Reading token from file %s", FILE));
			fis = new FileInputStream(FILE);
			return IOUtils.toString(fis, StandardCharsets.UTF_8.name());
		} catch (FileNotFoundException fnfe) {
			return null;
		} finally {
			if (fis != null) {
				fis.close();
			}
		}
	}

	/**
	 * Authenticates a user with the IDP and gets back the refresh token
	 * Basically, it performs and HTTP POST to the IDP, equivalent to the following:
	 * <code>
	 *     curl -d 'client_id=frontend-web-app' \
	 *   		-d "client_secret=$CLIENT_SECRET" \
	 *   		-d "username=alice" \
	 *   		-d "password=redhat" \
	 *   		-d "grant_type=password" \
	 *   		-d "scope=openid offline_access" \
	 *   		http://0.0.0.0:8080/realms/demo-realm/protocol/openid-connect/token
	 * </code>
	 * @param servletRequest
	 * @param servletContext
	 * @return
	 * @throws IOException
	 */
	public static String getOfflineToken(ServletRequest servletRequest, ServletContext servletContext) throws IOException {
		String OIDC_PROVIDER_URL = System.getenv("OIDC_PROVIDER_URL");
		String OIDC_REALM = System.getenv("OIDC_REALM");
		String OIDC_CLIENT_ID = System.getenv("OIDC_CLIENT_ID");
		String OIDC_CLIENT_SECRET = System.getenv("OIDC_CLIENT_SECRET");
		String OIDC_USERNAME = System.getenv("OIDC_USERNAME");
		String OIDC_PASSWORD = System.getenv("OIDC_PASSWORD");

		Form form = new Form();
		form.param("client_id", OIDC_CLIENT_ID);
		form.param("client_secret", OIDC_CLIENT_SECRET);
		form.param("username", OIDC_USERNAME);
		form.param("password", OIDC_PASSWORD);
		form.param("grant_type", "password");
		form.param("scope", "openid offline_access");

		try (Client client = ClientBuilder.newBuilder().hostnameVerifier(new NoopHostnameVerifier()).build()) {
			Invocation.Builder invocationBuilder = client
					.target(OIDC_PROVIDER_URL == null ? DEFAULT_OIDC_PROVIDER_URL : OIDC_PROVIDER_URL)
					.path(String.format("realms/%s/protocol/openid-connect/token", OIDC_REALM))
					.request();

			String refreshToken;
			try (Response response = invocationBuilder
					.post(Entity.form(form))) {
				String body = response.readEntity(String.class);
				Map<String, String> props;
				try (Jsonb jsb = JsonbBuilder.newBuilder().build()) {
					props = jsb.<Map<String, String>>fromJson(body, Map.class);
				} catch (Exception e) {
					throw new RuntimeException(e);
				}
				refreshToken = props.get("refresh_token");
			}

			if (refreshToken != null) {
				LOG.info("=====================================================");
				LOG.info("refreshToken -> " + refreshToken);
				LOG.info("=====================================================");
				return refreshToken;
			}
		}
		return null;
	}

	/**
	 * Uses the refresh token to obtain an access token;
	 * Basically, it performs and HTTP POST to the IDP, equivalent to the following:
	 * <code>
	 *	   curl \
	 *   		-d "client_id=frontend-web-app" \
	 *   		-d "client_secret=$CLIENT_SECRET" \
	 *   		-d "grant_type=refresh_token" \
	 *   		-d "refresh_token=$OFFLINE_TOKEN" \
	 *   		http://0.0.0.0:8080/realms/demo-realm/protocol/openid-connect/token
	 * </code>
	 * @param a
	 */
	public static String getAccessToken(ServletRequest servletRequest, ServletContext servletContext) throws IOException {
		final String refreshToken = loadToken();
		if (refreshToken == null) {
			LOG.info("=====================================================");
			LOG.info("No Offline Refresh Token available!");
			LOG.info("=====================================================");
			return null;
		}
		String OIDC_PROVIDER_URL = System.getenv("OIDC_PROVIDER_URL");
		String OIDC_REALM = System.getenv("OIDC_REALM");
		String OIDC_CLIENT_ID = System.getenv("OIDC_CLIENT_ID");
		String OIDC_CLIENT_SECRET = System.getenv("OIDC_CLIENT_SECRET");

		LOG.info("=====================================================");
		LOG.info("OIDC_PROVIDER_URL: " + OIDC_PROVIDER_URL);
		LOG.info("OIDC_REALM: " + OIDC_REALM);
		LOG.info("OIDC_CLIENT_ID: " + OIDC_CLIENT_ID);
		LOG.info("OIDC_CLIENT_SECRET: " + OIDC_CLIENT_SECRET);
		LOG.info("=====================================================");

		Form form = new Form();
		form.param("client_id", OIDC_CLIENT_ID);
		form.param("client_secret", OIDC_CLIENT_SECRET);
		form.param("grant_type", "refresh_token");
		form.param("refresh_token", refreshToken);

		try (Client client = ClientBuilder.newBuilder().hostnameVerifier(new NoopHostnameVerifier()).build()) {
			Invocation.Builder invocationBuilder = client
					.target(OIDC_PROVIDER_URL == null ? DEFAULT_OIDC_PROVIDER_URL : OIDC_PROVIDER_URL)
					.path(String.format("realms/%s/protocol/openid-connect/token", OIDC_REALM))
					.request();

			String accessToken;
			try (Response response = invocationBuilder
					.post(Entity.form(form))) {
				String body = response.readEntity(String.class);
				LOG.info("=====================================================");
				LOG.info("body -> " + body);
				LOG.info("=====================================================");
				Map<String, String> props;
				try (Jsonb jsb = JsonbBuilder.newBuilder().build()) {
					props = jsb.<Map<String, String>>fromJson(body, Map.class);
				} catch (Exception e) {
					throw new RuntimeException(e);
				}
				accessToken = props.get("access_token");
			}

			if (accessToken != null) {
				LOG.info("=====================================================");
				LOG.info("accessToken -> " + accessToken);
				LOG.info("=====================================================");
				return accessToken;
			}
		}
		return null;
	}
}
