/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.example;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.keycloak.adapters.spi.AuthenticationError;
import org.keycloak.adapters.spi.LogoutError;
import org.keycloak.common.util.StreamUtil;
import org.keycloak.common.util.Time;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.representations.RefreshToken;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.TokenUtil;
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
import org.wildfly.security.http.oidc.TokenValidator;

import javax.net.ssl.SSLSession;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
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

import static org.wildfly.security.http.oidc.Oidc.logToken;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class OfflineAccessPortalServlet extends HttpServlet {

    static final CallbackHandler HANDLER = new CallbackHandler() {

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            throw new UnsupportedCallbackException(callbacks[0]);
        }
    };


    @Override
    public void init() throws ServletException {
        getServletContext().setAttribute(HttpClient.class.getName(), new DefaultHttpClient());
    }

    @Override
    public void destroy() {
        getHttpClient().getConnectionManager().shutdown();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        try {
            if (req.getRequestURI().endsWith("/login")) {
                storeToken(req);
                req.getRequestDispatcher("/WEB-INF/pages/loginCallback.jsp").forward(req, resp);
                return;
            }

            String refreshToken = RefreshTokenDAO.loadToken();
            String refreshTokenInfo;
            boolean savedTokenAvailable;
            if (refreshToken == null) {
                refreshTokenInfo = "No token saved in database. Please login first";
                savedTokenAvailable = false;
            } else {
                RefreshToken refreshTokenDecoded = null;
                    refreshTokenDecoded = TokenUtil.getRefreshToken(refreshToken);
                String exp = (refreshTokenDecoded.getExpiration() == 0) ? "NEVER" : Time.toDate(refreshTokenDecoded.getExpiration()).toString();
                refreshTokenInfo = String.format("<p>Type: %s</p><p>ID: %s</p><p>Expires: %s</p>", refreshTokenDecoded.getType(), refreshTokenDecoded.getId(), exp);
                savedTokenAvailable = true;
            }
            req.setAttribute("tokenInfo", refreshTokenInfo);
            req.setAttribute("savedTokenAvailable", savedTokenAvailable);

            String customers;
            if (req.getRequestURI().endsWith("/loadCustomers")) {
                //customers = loadCustomers(req, refreshToken);
                customers = refreshTokenAndLoadCustomers(req, refreshToken);
            } else {
                customers = "";
            }
            req.setAttribute("customers", customers);

            req.getRequestDispatcher("/WEB-INF/pages/view.jsp").forward(req, resp);
        } catch (JWSInputException | org.wildfly.security.http.oidc.ServerRequest.HttpFailure e) {
            throw new ServletException(e);
        }
    }

    private void storeToken(HttpServletRequest req) throws IOException, JWSInputException {

        // ONLY org.wildfly.security.http.oidc.OidcSecurityContext is set
        System.out.println("=====================================================");
        req.getAttributeNames().asIterator().forEachRemaining(
                s -> System.out.println("HttpServletRequest.getAttribute(" + s + ") --> " + req.getAttribute(s))
        );
        System.out.println("=====================================================");

        // org.wildfly.security.http.oidc.OidcSecurityContext -> org.wildfly.security.http.oidc.RefreshableOidcSecurityContext
        RefreshableOidcSecurityContext ctx = (RefreshableOidcSecurityContext) req.getAttribute(OidcSecurityContext.class.getName());


        //RefreshableKeycloakSecurityContext ctx = (RefreshableKeycloakSecurityContext) req.getAttribute(KeycloakSecurityContext.class.getName());
        String refreshToken = ctx.getRefreshToken();
        IDToken idToken = ctx.getIDToken();
        AccessToken accessToken = ctx.getToken();
        System.out.println("=====================================================");
        System.out.println("refreshToken -> " + refreshToken);
        System.out.println("IDToken -> " + idToken);
        System.out.println("AccessToken -> " + accessToken);
        System.out.println("=====================================================");

        RefreshTokenDAO.saveToken(refreshToken);

        RefreshToken refreshTokenDecoded = TokenUtil.getRefreshToken(refreshToken);
        System.out.println("=====================================================");
        System.out.println("refreshTokenDecoded Issuer -> " + refreshTokenDecoded.getIssuer());
        System.out.println("refreshTokenDecoded Subject -> " + refreshTokenDecoded.getSubject());
        System.out.println("refreshTokenDecoded IssuedFor -> " + refreshTokenDecoded.getIssuedFor());
        System.out.println("refreshTokenDecoded SessionState -> " + refreshTokenDecoded.getSessionState());
        System.out.println("refreshTokenDecoded Nonce -> " + refreshTokenDecoded.getNonce());
        System.out.println("refreshTokenDecoded Scope -> " + refreshTokenDecoded.getScope());
        System.out.println("refreshTokenDecoded Type -> " + refreshTokenDecoded.getType());
        System.out.println("=====================================================");
        Boolean isOfflineToken = refreshTokenDecoded.getType().equals(TokenUtil.TOKEN_TYPE_OFFLINE);
        req.setAttribute("isOfflineToken", isOfflineToken);
    }



    public String refreshTokenAndLoadCustomers(final HttpServletRequest req, String refreshToken) throws org.wildfly.security.http.oidc.ServerRequest.HttpFailure, IOException {
        System.out.println("=====================================================");
        getServletContext().getAttributeNames().asIterator().forEachRemaining(
                s -> System.out.println("ServletContext.getAttribute(" + s + ") --> " + getServletContext().getAttribute(s))
        );
        System.out.println("=====================================================");
        req.getAttributeNames().asIterator().forEachRemaining(
                s -> System.out.println("HttpServletRequest.getAttribute(" + s + ") --> " + req.getAttribute(s))
        );
        System.out.println("=====================================================");

        OidcClientContext ctx = (OidcClientContext) getServletContext().getAttribute(OidcClientContext.class.getName());

        // block requests if the refresh accessToken herein stored is already being used to refresh the accessToken so that subsequent requests
        // can use the last refresh accessToken issued by the server. Note that this will only work for deployments using the session store
        // and, when running in a cluster, sticky sessions must be used.
        //
        String accessTokenString;
        AccessAndIDTokenResponse response;
        synchronized (this) {
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
                            (s, strings) -> ret.put(s,Arrays.asList(strings))
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

            OidcHttpFacade facade = new OidcHttpFacade(httpServerRequest, ctx, HANDLER);
            OidcClientConfiguration clientConfiguration = ctx.resolveDeployment(facade);
            response = org.wildfly.security.http.oidc.ServerRequest.invokeRefresh(clientConfiguration, refreshToken);
            accessTokenString = response.getAccessToken();
            String idTokenString = response.getIDToken();
            logToken("\taccess_token", accessTokenString);
            logToken("\tid_token", idTokenString);

            AccessToken accessToken;
            IDToken idToken;
            TokenValidator tokenValidator = TokenValidator.builder(clientConfiguration).build();
            TokenValidator.VerifiedTokens verifiedTokens = tokenValidator.parseAndVerifyToken(idTokenString, accessTokenString);
            idToken = verifiedTokens.getIdToken();
            accessToken = verifiedTokens.getAccessToken();
        }

        return loadCustomersFromRemoteService(req, accessTokenString);
    }

    private String loadCustomersFromRemoteService(HttpServletRequest req, String accessToken) throws IOException {
        // Load customers now
        HttpGet get = new HttpGet("http://0.0.0.0:8280/database-service/customers");
        get.addHeader("Authorization", String.format("Bearer %s", accessToken));
        get.addHeader("Accept","application/json");

        System.out.println("loadCustomers: " + get.getURI());
        System.out.println("Bearer " + accessToken);

        System.out.println(
                String.format("curl -v http://0.0.0.0:8280/database-service/customers" +
                " -H \"Accept: application/json\"" +
                " -H \"Authorization: Bearer %s\"", accessToken));

        HttpResponse response = getHttpClient().execute(get);
        InputStream is = response.getEntity().getContent();
        System.out.println("loadCustomers: " + response.getStatusLine().getStatusCode() + " - " + response.getStatusLine().getReasonPhrase());
        try {
            if (response.getStatusLine().getStatusCode() != 200) {
                return "Error when loading customer. Status: " + response.getStatusLine().getStatusCode() + ", error: " + StreamUtil.readString(is);
            } else {
                List<String> list = JsonSerialization.readValue(is, TypedList.class);
                StringBuilder result = new StringBuilder();
                for (String customer : list) {
                    result.append(customer + "<br />");
                }
                return result.toString();
            }
        } finally {
            is.close();
        }
    }


    private OidcClientConfiguration getDeployment(HttpServletRequest request) throws ServletException {

        // The facade object is needed just if you have relative "auth-server-url" in keycloak.json. Otherwise you can call deploymentContext.resolveDeployment(null)
        //HttpFacade facade = getFacade(servletRequest);

        System.out.println("=====================================================");
        getServletContext().getAttributeNames().asIterator().forEachRemaining(
                s -> System.out.println("ServletContext.getAttribute(" + s + ") --> " + getServletContext().getAttribute(s))
        );
        System.out.println("=====================================================");

        OidcClientContext ctx = (OidcClientContext) getServletContext().getAttribute(OidcClientContext.class.getName());
        OidcHttpFacade facade = getFacade(request, ctx);


        return ctx.resolveDeployment(facade);

        //AdapterDeploymentContext deploymentContext = (AdapterDeploymentContext) getServletContext().getAttribute(AdapterDeploymentContext.class.getName());
        //if (deploymentContext == null) {
        //    throw new ServletException("AdapterDeploymentContext not set");
        //}
        //return deploymentContext.resolveDeployment(facade);
    }

    // TODO: Merge with facade in ServletOAuthClient and move to some common servlet adapter
    private OidcHttpFacade getFacade(final HttpServletRequest servletRequest, OidcClientContext ctx) {
        return new OidcHttpFacade(null, ctx, null) {

            @Override
            public Request getRequest() {
                return new Request() {

                    private InputStream inputStream;

                    @Override
                    public String getMethod() {
                        return servletRequest.getMethod();
                    }

                    @Override
                    public String getURI() {
                        return servletRequest.getRequestURL().toString();
                    }

                    @Override
                    public String getRelativePath() {
                        return servletRequest.getServletPath();
                    }

                    @Override
                    public boolean isSecure() {
                        return servletRequest.isSecure();
                    }

                    @Override
                    public String getQueryParamValue(String param) {
                        return servletRequest.getParameter(param);
                    }

                    @Override
                    public String getFirstParam(String param) {
                        return servletRequest.getParameter(param);
                    }

                    @Override
                    public Cookie getCookie(String cookieName) {
                        // not needed
                        return null;
                    }

                    @Override
                    public String getHeader(String name) {
                        return servletRequest.getHeader(name);
                    }

                    @Override
                    public List<String> getHeaders(String name) {
                        // not needed
                        return null;
                    }

                    @Override
                    public InputStream getInputStream() {
                        return getInputStream(false);
                    }

                    @Override
                    public InputStream getInputStream(boolean buffered) {
                        if (inputStream != null) {
                            return inputStream;
                        }

                        if (buffered) {
                            try {
                                return inputStream = new BufferedInputStream(servletRequest.getInputStream());
                            } catch (IOException e) {
                                throw new RuntimeException(e);
                            }
                        }

                        try {
                            return servletRequest.getInputStream();
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    }

                    @Override
                    public String getRemoteAddr() {
                        return servletRequest.getRemoteAddr();
                    }

                    @Override
                    public void setError(org.wildfly.security.http.oidc.AuthenticationError error) {
                        servletRequest.setAttribute(AuthenticationError.class.getName(), error);
                    }

                    @Override
                    public void setError(org.wildfly.security.http.oidc.LogoutError error) {
                        servletRequest.setAttribute(LogoutError.class.getName(), error);
                    }

                };
            }

            @Override
            public Response getResponse() {
                throw new IllegalStateException("Not yet implemented");
            }

            @Override
            public Certificate[] getCertificateChain() {
                throw new IllegalStateException("Not yet implemented");
            }
        };
    }

    private HttpClient getHttpClient() {
        return (HttpClient) getServletContext().getAttribute(HttpClient.class.getName());
    }

    static class TypedList extends ArrayList<String> {
    }
}
