package org.wildfly.security.examples.app;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.io.IOUtils;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerCookie;
import org.wildfly.security.http.HttpServerMechanismsResponder;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.Scope;
import org.wildfly.security.http.oidc.AccessAndIDTokenResponse;
import org.wildfly.security.http.oidc.OidcClientConfiguration;
import org.wildfly.security.http.oidc.OidcClientContext;
import org.wildfly.security.http.oidc.OidcHttpFacade;
import org.wildfly.security.http.oidc.ServerRequest;

import javax.net.ssl.SSLSession;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import static org.wildfly.security.http.oidc.ServerRequest.invokeRefresh;

public class RefreshTokenUtils {

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


	public static String getAccessToken(ServletRequest servletRequest, ServletContext servletContext) throws IOException {
		String refreshToken = RefreshTokenUtils.loadToken();

		if (refreshToken != null) {
			LOG.info("=====================================================");
			LOG.info("refreshToken -> " + refreshToken);
			LOG.info("=====================================================");
			HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;

			OidcClientContext ctx = (OidcClientContext) servletContext.getAttribute(OidcClientContext.class.getName());

			OidcHttpFacade facade = new OidcHttpFacade(createHttpServerRequest(httpServletRequest), ctx, HANDLER);
			OidcClientConfiguration deployment = ctx.resolveDeployment(facade);

			try {
				AccessAndIDTokenResponse accessAndIDTokenResponse = invokeRefresh(deployment, refreshToken);
				saveToken(accessAndIDTokenResponse.getRefreshToken());
				return accessAndIDTokenResponse.getAccessToken();
			} catch (ServerRequest.HttpFailure e) {
				LOG.severe(String.format("Error in invokeRefresh: %s", e.getError()));
			}
		}
		return null;
	}

	private static HttpServerRequest createHttpServerRequest(final HttpServletRequest request) {
		return new HttpServerRequest() {

			final HttpScope scope = new HttpScope() {
				@Override
				public String getID() {
					return request.getRequestId();
				}
			};
			@Override
			public HttpScope getScope(Scope scope) {
				return this.scope;
			}

			@Override
			public Collection<String> getScopeIds(Scope scope) {
				return Collections.singletonList(this.scope.getID());
			}

			@Override
			public HttpScope getScope(Scope scope, String id) {
				return (id != null && id.equalsIgnoreCase(request.getRequestId())) ? this.scope : null;
			}

			@Override
			public List<String> getRequestHeaderValues(String headerName) {
				return Collections.singletonList(request.getHeader(headerName));
			}

			@Override
			public String getFirstRequestHeaderValue(String headerName) {
				return request.getHeader(headerName);
			}

			@Override
			public SSLSession getSSLSession() {
				LOG.info("Dummy getSSLSession: always returns null SSLSession!");
				return null;
			}

			@Override
			public Certificate[] getPeerCertificates() {
				LOG.info("Dummy getPeerCertificates: always returns empty Certificate[]!");
				return new Certificate[0];
			}

			@Override
			public void noAuthenticationInProgress(HttpServerMechanismsResponder responder) {
				LOG.info("Dummy noAuthenticationInProgress");
			}

			@Override
			public void authenticationInProgress(HttpServerMechanismsResponder responder) {
				LOG.info("Dummy authenticationInProgress");
			}

			@Override
			public void authenticationComplete(HttpServerMechanismsResponder responder) {
				LOG.info("Dummy authenticationComplete");
			}

			@Override
			public void authenticationComplete(HttpServerMechanismsResponder responder, Runnable logoutHandler) {
				LOG.info("Dummy authenticationComplete");
			}

			@Override
			public void authenticationFailed(String message, HttpServerMechanismsResponder responder) {
				LOG.info("Dummy authenticationFailed");
			}

			@Override
			public void badRequest(HttpAuthenticationException failure, HttpServerMechanismsResponder responder) {
				LOG.info("Dummy badRequest");
			}

			@Override
			public String getRequestMethod() {
				return request.getMethod();
			}

			@Override
			public URI getRequestURI() {
				return URI.create(request.getRequestURI());
			}

			@Override
			public String getRequestPath() {
				return request.getServletPath();
			}

			@Override
			public Map<String, List<String>> getParameters() {
				Map<String, List<String>> ret = new HashMap<>();
				request.getParameterMap().forEach(
						(s, as) -> ret.put(s, new ArrayList<>(Arrays.asList(as)))
				);
				return ret;
			}

			@Override
			public Set<String> getParameterNames() {
				Set<String> ret = new HashSet<>();
				request.getParameterNames().asIterator().forEachRemaining(ret::add);
				return ret;
			}

			@Override
			public List<String> getParameterValues(String name) {
				return Collections.singletonList(request.getParameter(name));
			}

			@Override
			public String getFirstParameterValue(String name) {
				return request.getParameter(name);
			}

			@Override
			public List<HttpServerCookie> getCookies() {
				return Arrays.stream(request.getCookies()).map(
						cookie -> HttpServerCookie.getInstance(
								cookie.getName(),
								cookie.getValue(),
								cookie.getDomain(),
								cookie.getMaxAge(),
								cookie.getPath(),
								cookie.getSecure(),
								0,
								cookie.isHttpOnly()
						)
				).collect(Collectors.toList());
			}

			@Override
			public InputStream getInputStream() {
				try {
					return request.getInputStream();
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}

			@Override
			public InetSocketAddress getSourceAddress() {
				return new InetSocketAddress(request.getRemoteHost(), request.getRemotePort());
			}

			@Override
			public boolean suspendRequest() {
				return false;
			}

			@Override
			public boolean resumeRequest() {
				return false;
			}

			@Override
			public String getRemoteUser() {
				return request.getRemoteUser();
			}
		};
	}
}
