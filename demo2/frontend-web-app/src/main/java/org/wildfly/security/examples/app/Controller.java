/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.examples.app;

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.core.Response;
import org.wildfly.security.http.oidc.AccessToken;
import org.wildfly.security.http.oidc.IDToken;
import org.wildfly.security.http.oidc.OidcSecurityContext;
import org.wildfly.security.http.oidc.RefreshableOidcSecurityContext;
import org.wildfly.security.http.oidc.ServerRequest;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.util.logging.Logger;

public class Controller {

	static final CallbackHandler HANDLER = new CallbackHandler() {

		@Override
		public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
			throw new UnsupportedCallbackException(callbacks[0]);
		}
	};

	private static final Logger LOG = Logger.getLogger(Controller.class.getName());
	private static final String AUTHZ_HEADER = "Authorization";
	private static final String ENDPOINT_URL = "http://localhost:8090/service/";

	public boolean isLoggedIn(HttpServletRequest req) throws IOException {
		LOG.info("=====================================================");
		req.getAttributeNames().asIterator().forEachRemaining(
				s -> LOG.info("HttpServletRequest.getAttribute(" + s + ") --> " + req.getAttribute(s))
		);
		LOG.info("=====================================================");
		OidcSecurityContext ctx = getOidcSecurityContext(req);
		return ctx != null;
	}

	public String logout(HttpServletRequest req) {
		HttpSession session = req.getSession();
		if (session != null) {
			session.invalidate();
		}
		return "Successfully logged out!";
	}

	public String storeRefreshToken(HttpServletRequest req) throws IOException {
		OidcSecurityContext ctx = getOidcSecurityContext(req);
		String refreshToken = null;
		IDToken idToken = null;
		AccessToken accessToken = null;
		if (ctx != null) {
			RefreshableOidcSecurityContext rCtx = RefreshableOidcSecurityContext.class.cast(ctx);
			refreshToken = rCtx.getRefreshToken();
			idToken = rCtx.getIDToken();
			accessToken = rCtx.getToken();
			LOG.info("=====================================================");
			LOG.info("refreshToken -> " + refreshToken);
			LOG.info("IDToken -> " + idToken);
			LOG.info("AccessToken -> " + accessToken);
			LOG.info("=====================================================");
			RefreshTokenUtils.saveToken(refreshToken);
		}
		return refreshToken;
	}

	public String getMessage(HttpServletRequest req, ServletContext servletContext) throws IOException, ServerRequest.HttpFailure {
		String action = getAction(req);
		if (action.equals("")) return "";
		OidcSecurityContext oidcSecurityContext = getOidcSecurityContext(req);
		String target = System.getenv("BACKEND_SERVICE_URL");
		Invocation.Builder invocationBuilder = ClientBuilder.newClient().target(target == null ? ENDPOINT_URL : target).path(action).request();
		Response response;
		if (oidcSecurityContext != null) {
			// ==============================================================================
			// User is logged in: we have a super fresh access token
			// ==============================================================================
			LOG.info("### User is logged in: we have a super fresh access token ...");
			response = invocationBuilder.header(AUTHZ_HEADER, String.format("Bearer %s", oidcSecurityContext.getTokenString())).get();
		} else {
			String accessToken = RefreshTokenUtils.getAccessToken(req, servletContext);
			if (accessToken != null) {
				// ==============================================================================
				// User logged out but logged in previously: we stored the previous refresh token
				// which we use to get a new access token from the IDSP
				// ==============================================================================
				LOG.info("### User logged out but logged in previously ...");
				response = invocationBuilder.header(AUTHZ_HEADER, String.format("Bearer %s", accessToken)).get();
			} else {
				// ==============================================================================
				// User has NEVER logged in yet
				// ==============================================================================
				LOG.info("### User has NEVER logged in yet ...");
				response = invocationBuilder.get();
			}
		}
		String message;
		if (response.getStatus() == 200) {
			message = response.readEntity(String.class);
		} else {
			message = "<span class='error'>" + response.getStatus() + " " + response.getStatusInfo() + "</span>";
		}
		response.close();
		return message;
	}

	private OidcSecurityContext getOidcSecurityContext(HttpServletRequest req) {
		return (OidcSecurityContext) req.getAttribute(OidcSecurityContext.class.getName());
	}

	private String getAction(HttpServletRequest req) {
		if (req.getParameter("action") == null) return "";
		return req.getParameter("action");
	}
}
