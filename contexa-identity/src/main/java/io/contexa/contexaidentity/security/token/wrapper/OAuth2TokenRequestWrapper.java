/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaidentity.security.token.wrapper;

import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Presents the current request to the in-process Spring Authorization Server token endpoint as a
 * client-authenticated token request carrying only the given grant parameters.
 */
public class OAuth2TokenRequestWrapper extends HttpServletRequestWrapper {

    /**
     * Request attribute that is present only on token requests built by this wrapper. External HTTP
     * requests cannot set request attributes, so it marks a request as issued inside the process.
     */
    public static final String INTERNAL_REQUEST_ATTRIBUTE = OAuth2TokenRequestWrapper.class.getName() + ".INTERNAL";

    private static final String TOKEN_ENDPOINT = "/oauth2/token";

    private final String clientId;
    private final String clientSecret;
    private final Map<String, String[]> oauth2Parameters;

    public OAuth2TokenRequestWrapper(
            HttpServletRequest request,
            String clientId,
            String clientSecret,
            Map<String, String[]> oauth2Parameters) {
        super(request);
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.oauth2Parameters = Collections.unmodifiableMap(new LinkedHashMap<>(oauth2Parameters));
    }

    public static OAuth2TokenRequestWrapper authenticatedUser(
            HttpServletRequest request,
            String username,
            String deviceId,
            String clientId,
            String clientSecret,
            Set<String> scopes) {
        Map<String, String[]> params = new LinkedHashMap<>();
        params.put(OAuth2ParameterNames.GRANT_TYPE,
                new String[]{AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER.getValue()});
        params.put("username", new String[]{username});
        if (deviceId != null) {
            params.put("device_id", new String[]{deviceId});
        }
        if (scopes != null && !scopes.isEmpty()) {
            params.put(OAuth2ParameterNames.SCOPE, new String[]{String.join(" ", scopes)});
        }
        return new OAuth2TokenRequestWrapper(request, clientId, clientSecret, params);
    }

    public static OAuth2TokenRequestWrapper refreshToken(
            HttpServletRequest request,
            String refreshToken,
            String clientId,
            String clientSecret) {
        Map<String, String[]> params = new LinkedHashMap<>();
        params.put(OAuth2ParameterNames.GRANT_TYPE, new String[]{AuthorizationGrantType.REFRESH_TOKEN.getValue()});
        params.put(OAuth2ParameterNames.REFRESH_TOKEN, new String[]{refreshToken});
        return new OAuth2TokenRequestWrapper(request, clientId, clientSecret, params);
    }

    @Override
    public Object getAttribute(String name) {
        if (INTERNAL_REQUEST_ATTRIBUTE.equals(name)) {
            return Boolean.TRUE;
        }
        return super.getAttribute(name);
    }

    @Override
    public String getRequestURI() {
        return TOKEN_ENDPOINT;
    }

    @Override
    public StringBuffer getRequestURL() {
        StringBuffer url = new StringBuffer();
        url.append(getScheme())
           .append("://")
           .append(getServerName());
        int port = getServerPort();
        if (port != 80 && port != 443) {
            url.append(':').append(port);
        }
        url.append(TOKEN_ENDPOINT);
        return url;
    }

    @Override
    public String getServletPath() {
        return TOKEN_ENDPOINT;
    }

    @Override
    public String getPathInfo() {
        return null;
    }

    /**
     * The token endpoint treats any parameter whose name appears in the query string as a query
     * parameter and ignores it, so the original query string must not leak into the token request.
     */
    @Override
    public String getQueryString() {
        return null;
    }

    @Override
    public String getParameter(String name) {
        String[] values = oauth2Parameters.get(name);
        return (values != null && values.length > 0) ? values[0] : null;
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        return oauth2Parameters;
    }

    @Override
    public Enumeration<String> getParameterNames() {
        return Collections.enumeration(oauth2Parameters.keySet());
    }

    @Override
    public String[] getParameterValues(String name) {
        return oauth2Parameters.get(name);
    }

    @Override
    public String getHeader(String name) {
        if (HttpHeaders.AUTHORIZATION.equalsIgnoreCase(name)) {
            String credentials = clientId + ":" + clientSecret;
            String base64Credentials = Base64.getEncoder()
                    .encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
            return "Basic " + base64Credentials;
        }
        return super.getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        if (HttpHeaders.AUTHORIZATION.equalsIgnoreCase(name)) {
            return Collections.enumeration(Collections.singletonList(getHeader(name)));
        }
        return super.getHeaders(name);
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        Set<String> headerNames = new HashSet<>();
        Enumeration<String> originalHeaders = super.getHeaderNames();
        if (originalHeaders != null) {
            while (originalHeaders.hasMoreElements()) {
                headerNames.add(originalHeaders.nextElement());
            }
        }
        headerNames.add(HttpHeaders.AUTHORIZATION);
        return Collections.enumeration(headerNames);
    }

    @Override
    public String getMethod() {
        return "POST";
    }
}
