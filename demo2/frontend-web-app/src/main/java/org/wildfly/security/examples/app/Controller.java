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
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.core.GenericType;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.core.Response;
import org.apache.commons.io.IOUtils;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerCookie;
import org.wildfly.security.http.HttpServerMechanismsResponder;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.Scope;
import org.wildfly.security.http.oidc.AccessAndIDTokenResponse;
import org.wildfly.security.http.oidc.AccessToken;
import org.wildfly.security.http.oidc.IDToken;
import org.wildfly.security.http.oidc.OidcClientConfiguration;
import org.wildfly.security.http.oidc.OidcClientContext;
import org.wildfly.security.http.oidc.OidcHttpFacade;
import org.wildfly.security.http.oidc.OidcSecurityContext;
import org.wildfly.security.http.oidc.RefreshableOidcSecurityContext;
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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.logging.Logger;

public class Controller {

    public static final String FILE = System.getProperty("java.io.tmpdir") + "/" +
            (System.getenv("OIDC_CLIENT_ID") == null ? "frontend-web-app" : System.getenv("OIDC_CLIENT_ID"));

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
        OidcSecurityContext ctx = getOidcSecurityContext(req);

        LOG.info("=====================================================");
        req.getAttributeNames().asIterator().forEachRemaining(
                s -> LOG.info("HttpServletRequest.getAttribute(" + s + ") --> " + req.getAttribute(s))
        );
        LOG.info("=====================================================");

        if (ctx != null) {
            RefreshableOidcSecurityContext rCtx = RefreshableOidcSecurityContext.class.cast(ctx);
            String refreshToken = rCtx.getRefreshToken();
            IDToken idToken = rCtx.getIDToken();
            AccessToken accessToken = rCtx.getToken();
            LOG.info("=====================================================");
            LOG.info("refreshToken -> " + refreshToken);
            LOG.info("IDToken -> " + idToken);
            LOG.info("AccessToken -> " + accessToken);
            LOG.info("=====================================================");
            saveToken(refreshToken);
        }
        return ctx != null;
    }

    public String getMessage(HttpServletRequest req, ServletContext servletContext) throws IOException, ServerRequest.HttpFailure {
        String action = getAction(req);
        if (action.equals("")) return "";
        OidcSecurityContext oidcSecurityContext = getOidcSecurityContext(req);
        String target = System.getenv("BACKEND_SERVICE_URL");
        Invocation.Builder invocationBuilder = ClientBuilder.newClient().target(target == null ? ENDPOINT_URL : target).path(action).request();
        Response response;
        if (oidcSecurityContext != null) {
            String authzHeaderValue = "Bearer " + oidcSecurityContext.getTokenString();
            LOG.info(AUTHZ_HEADER + ": " + authzHeaderValue);
            response = invocationBuilder.header(AUTHZ_HEADER, authzHeaderValue).get();
        } else {
            String refreshToken = loadToken();
            if (refreshToken != null) {
                LOG.info("=====================================================");
                LOG.info("refreshToken -> " + refreshToken);
                LOG.info("=====================================================");
                String authzHeaderValue = "Bearer " + getAccessToken(refreshToken, req, servletContext);
                response = invocationBuilder.header(AUTHZ_HEADER, authzHeaderValue).get();
            } else {
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

    private String getAccessToken(String refreshToken, HttpServletRequest req, ServletContext servletContext) {
        String accessTokenString = null;
        try {
            OidcClientContext ctx = (OidcClientContext) servletContext.getAttribute(OidcClientContext.class.getName());
            OidcHttpFacade facade = new OidcHttpFacade(getHttpServerRequest(req), ctx, HANDLER);
            OidcClientConfiguration clientConfiguration = ctx.resolveDeployment(facade);
            AccessAndIDTokenResponse response = org.wildfly.security.http.oidc.ServerRequest.invokeRefresh(clientConfiguration, refreshToken);
            accessTokenString = response.getAccessToken();
            LOG.info("=====================================================");
            LOG.info("NEW accessTokenString -> " + accessTokenString);
            LOG.info("=====================================================");
        } catch (Exception err) {
            LOG.severe("Error using refresh token: " + err.getMessage());
        }
        return accessTokenString;
    }

    private HttpServerRequest getHttpServerRequest(HttpServletRequest req) {
        HttpServerRequest httpServerRequest = new HttpServerRequest() {

            @Override
            public HttpScope getScope(Scope scope) {
                return null;
            }

            @Override
            public Collection<String> getScopeIds(Scope scope) {
                return null;
            }

            @Override
            public HttpScope getScope(Scope scope, String s) {
                return null;
            }

            @Override
            public List<String> getRequestHeaderValues(String s) {
                final List<String> ret = new ArrayList<>();
                req.getHeaderNames().asIterator().forEachRemaining(
                        s1 -> ret.add(req.getHeader(s1))
                );
                return ret;
            }

            @Override
            public String getFirstRequestHeaderValue(String s) {
                return null;
            }

            @Override
            public SSLSession getSSLSession() {
                return null;
            }

            @Override
            public Certificate[] getPeerCertificates() {
                return new Certificate[0];
            }

            @Override
            public void noAuthenticationInProgress(HttpServerMechanismsResponder httpServerMechanismsResponder) {

            }

            @Override
            public void noAuthenticationInProgress() {
                HttpServerRequest.super.noAuthenticationInProgress();
            }

            @Override
            public void authenticationInProgress(HttpServerMechanismsResponder httpServerMechanismsResponder) {

            }

            @Override
            public void authenticationComplete(HttpServerMechanismsResponder httpServerMechanismsResponder) {

            }

            @Override
            public void authenticationComplete(HttpServerMechanismsResponder httpServerMechanismsResponder, Runnable runnable) {

            }

            @Override
            public void authenticationComplete() {
                HttpServerRequest.super.authenticationComplete();
            }

            @Override
            public void authenticationFailed(String s, HttpServerMechanismsResponder httpServerMechanismsResponder) {

            }

            @Override
            public void authenticationFailed(String message) {
                HttpServerRequest.super.authenticationFailed(message);
            }

            @Override
            public void badRequest(HttpAuthenticationException e, HttpServerMechanismsResponder httpServerMechanismsResponder) {

            }

            @Override
            public void badRequest(HttpAuthenticationException failure) {
                HttpServerRequest.super.badRequest(failure);
            }

            @Override
            public String getRequestMethod() {
                return req.getMethod();
            }

            @Override
            public URI getRequestURI() {
                return URI.create(req.getRequestURI());
            }

            @Override
            public String getRequestPath() {
                return null;
            }

            @Override
            public String getRemoteUser() {
                return req.getRemoteUser();
            }

            @Override
            public Map<String, List<String>> getParameters() {
                Map<String, List<String>> ret = new HashMap<>();
                req.getParameterMap().forEach(
                        (s, strings) -> ret.put(s, Arrays.asList(strings))
                );
                return ret;
            }

            @Override
            public Set<String> getParameterNames() {
                Set<String> ret = new HashSet<>();
                req.getParameterNames().asIterator().forEachRemaining(ret::add);
                return ret;
            }

            @Override
            public List<String> getParameterValues(String s) {
                return Arrays.asList(req.getParameterValues(s));
            }

            @Override
            public String getFirstParameterValue(String s) {
                return null;
            }

            @Override
            public List<HttpServerCookie> getCookies() {
                List<HttpServerCookie> cookies = new ArrayList<>();
                Arrays.stream(req.getCookies()).iterator().forEachRemaining(
                        cookie -> cookies.add(HttpServerCookie.getInstance(
                                cookie.getName(),
                                cookie.getValue(),
                                cookie.getDomain(),
                                cookie.getMaxAge(),
                                cookie.getPath(),
                                cookie.getSecure(),
                                0,
                                cookie.isHttpOnly()
                        ))
                );
                return cookies;
            }

            @Override
            public InputStream getInputStream() {
                try {
                    return req.getInputStream();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }

            @Override
            public InetSocketAddress getSourceAddress() {
                return new InetSocketAddress(req.getRemoteAddr(),req.getRemotePort());
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
            public void setRequestInputStreamSupplier(Supplier<InputStream> requestInputStreamSupplier) {
                HttpServerRequest.super.setRequestInputStreamSupplier(requestInputStreamSupplier);
            }
        };
        return httpServerRequest;
    }

    private OidcSecurityContext getOidcSecurityContext(HttpServletRequest req) {
        return (OidcSecurityContext) req.getAttribute(OidcSecurityContext.class.getName());
    }

    private String getAction(HttpServletRequest req) {
        if (req.getParameter("action") == null) return "";
        return req.getParameter("action");
    }

    private static void saveToken(final String token) throws IOException {
        PrintWriter writer = null;
        try {
            LOG.info(String.format("Storing token %s in file %s",token,FILE));
            writer = new PrintWriter(new BufferedWriter(new FileWriter(FILE)));
            writer.print(token);
        } finally {
            if (writer != null) {
                writer.close();
            }
        }
    }

    private static String loadToken() throws IOException {
        FileInputStream fis = null;
        try {
            LOG.info(String.format("Reading token from file %s",FILE));
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
}
