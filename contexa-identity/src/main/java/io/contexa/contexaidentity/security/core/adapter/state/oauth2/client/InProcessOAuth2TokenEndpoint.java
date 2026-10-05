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
package io.contexa.contexaidentity.security.core.adapter.state.oauth2.client;

import io.contexa.contexaidentity.security.token.wrapper.CapturedTokenEndpointResponse;
import io.contexa.contexaidentity.security.token.wrapper.OAuth2TokenRequestWrapper;
import jakarta.servlet.Filter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.MediaType;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.function.Function;

/**
 * Sends token requests to the Spring Authorization Server token endpoint of this application without
 * an HTTP round trip. The endpoint filter is taken from the security filter chain, the internal client
 * is authenticated with the Spring client-secret provider, and the grant is processed by the regular
 * Spring Authorization Server authentication providers.
 */
public final class InProcessOAuth2TokenEndpoint {

    private static final String TOKEN_ENDPOINT_FILTER_NAME = "OAuth2TokenEndpointFilter";

    private final ObjectProvider<FilterChainProxy> filterChainProxyProvider;
    private final AuthenticationConverter clientSecretBasicConverter;
    private final AuthenticationProvider clientSecretAuthenticationProvider;
    private final OAuth2ErrorHttpMessageConverter errorConverter = new OAuth2ErrorHttpMessageConverter();

    private volatile Filter tokenEndpointFilter;

    public InProcessOAuth2TokenEndpoint(ObjectProvider<FilterChainProxy> filterChainProxyProvider,
                                        AuthenticationConverter clientSecretBasicConverter,
                                        AuthenticationProvider clientSecretAuthenticationProvider) {
        Assert.notNull(filterChainProxyProvider, "filterChainProxyProvider cannot be null");
        Assert.notNull(clientSecretBasicConverter, "clientSecretBasicConverter cannot be null");
        Assert.notNull(clientSecretAuthenticationProvider, "clientSecretAuthenticationProvider cannot be null");
        this.filterChainProxyProvider = filterChainProxyProvider;
        this.clientSecretBasicConverter = clientSecretBasicConverter;
        this.clientSecretAuthenticationProvider = clientSecretAuthenticationProvider;
    }

    /**
     * Exchanges a grant for tokens. The request and response default to the ones bound to the current
     * thread when they are not given.
     */
    public OAuth2AccessTokenResponse exchange(@Nullable HttpServletRequest request,
                                              @Nullable HttpServletResponse response,
                                              Function<HttpServletRequest, OAuth2TokenRequestWrapper> tokenRequestFactory) {
        Assert.notNull(tokenRequestFactory, "tokenRequestFactory cannot be null");

        HttpServletRequest currentRequest = request != null ? request : currentServletRequest();
        HttpServletResponse currentResponse = response != null ? response : currentServletResponse();
        if (currentRequest == null || currentResponse == null) {
            throw new OAuth2AuthorizationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The internal token engine requires the current HTTP request and response", null));
        }

        Filter endpoint = resolveTokenEndpointFilter();
        OAuth2TokenRequestWrapper tokenRequest = tokenRequestFactory.apply(currentRequest);
        CapturedTokenEndpointResponse endpointResponse = new CapturedTokenEndpointResponse(currentResponse);
        SecurityContext originalContext = SecurityContextHolder.getContext();
        try {
            SecurityContextHolder.clearContext();
            SecurityContext clientContext = SecurityContextHolder.createEmptyContext();
            clientContext.setAuthentication(authenticateClient(tokenRequest));
            SecurityContextHolder.setContext(clientContext);

            endpoint.doFilter(tokenRequest, endpointResponse, (req, res) -> {
            });

            Authentication result = SecurityContextHolder.getContext().getAuthentication();
            if (result instanceof OAuth2AccessTokenAuthenticationToken tokenAuthentication) {
                return buildTokenResponse(tokenAuthentication);
            }
            throw new OAuth2AuthorizationException(readEndpointError(endpointResponse));
        } catch (OAuth2AuthenticationException ex) {
            throw new OAuth2AuthorizationException(ex.getError(), ex);
        } catch (IOException | ServletException ex) {
            throw new OAuth2AuthorizationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The internal token endpoint failed: " + ex.getMessage(), null), ex);
        } finally {
            SecurityContextHolder.setContext(originalContext);
        }
    }

    private Authentication authenticateClient(OAuth2TokenRequestWrapper tokenRequest) {
        Authentication clientAuthRequest = clientSecretBasicConverter.convert(tokenRequest);
        if (clientAuthRequest == null) {
            throw new OAuth2AuthorizationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
                    "Client authentication failed - no credentials found", null));
        }
        Authentication clientAuthResult = clientSecretAuthenticationProvider.authenticate(clientAuthRequest);
        if (clientAuthResult == null || !clientAuthResult.isAuthenticated()) {
            throw new OAuth2AuthorizationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
                    "Client authentication failed", null));
        }
        return clientAuthResult;
    }

    private OAuth2Error readEndpointError(CapturedTokenEndpointResponse endpointResponse) {
        byte[] body = endpointResponse.getCapturedBody();
        if (body.length > 0) {
            try {
                return errorConverter.read(OAuth2Error.class, jsonMessage(body));
            } catch (Exception ex) {
                return new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                        "Unreadable token endpoint error response (status " + endpointResponse.getStatus() + ")", null);
            }
        }
        return new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                "The token endpoint returned no token (status " + endpointResponse.getStatus() + ")", null);
    }

    private static HttpInputMessage jsonMessage(byte[] body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return new HttpInputMessage() {
            @Override
            public InputStream getBody() {
                return new ByteArrayInputStream(body);
            }

            @Override
            public HttpHeaders getHeaders() {
                return headers;
            }
        };
    }

    private static OAuth2AccessTokenResponse buildTokenResponse(OAuth2AccessTokenAuthenticationToken authentication) {
        OAuth2AccessToken accessToken = authentication.getAccessToken();
        OAuth2RefreshToken refreshToken = authentication.getRefreshToken();
        Map<String, Object> additionalParameters = authentication.getAdditionalParameters();

        OAuth2AccessTokenResponse.Builder builder = OAuth2AccessTokenResponse
                .withToken(accessToken.getTokenValue())
                .tokenType(accessToken.getTokenType())
                .scopes(accessToken.getScopes());
        if (accessToken.getExpiresAt() != null && accessToken.getIssuedAt() != null) {
            builder.expiresIn(ChronoUnit.SECONDS.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()));
        }
        if (refreshToken != null) {
            builder.refreshToken(refreshToken.getTokenValue());
        }
        if (!CollectionUtils.isEmpty(additionalParameters)) {
            builder.additionalParameters(additionalParameters);
        }
        return builder.build();
    }

    private Filter resolveTokenEndpointFilter() {
        Filter filter = tokenEndpointFilter;
        if (filter != null) {
            return filter;
        }
        FilterChainProxy filterChainProxy = filterChainProxyProvider.getIfAvailable();
        if (filterChainProxy == null) {
            throw new OAuth2AuthorizationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "FilterChainProxy is not available for the internal token engine", null));
        }
        for (SecurityFilterChain chain : filterChainProxy.getFilterChains()) {
            for (Filter candidate : chain.getFilters()) {
                if (candidate.getClass().getName().contains(TOKEN_ENDPOINT_FILTER_NAME)) {
                    tokenEndpointFilter = candidate;
                    return candidate;
                }
            }
        }
        throw new IllegalStateException(
                "OAuth2TokenEndpointFilter not found in FilterChainProxy. "
                        + "Ensure Spring Authorization Server is properly configured.");
    }

    @Nullable
    private static HttpServletRequest currentServletRequest() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        return attributes instanceof ServletRequestAttributes servletAttributes ? servletAttributes.getRequest() : null;
    }

    @Nullable
    private static HttpServletResponse currentServletResponse() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        return attributes instanceof ServletRequestAttributes servletAttributes ? servletAttributes.getResponse() : null;
    }
}
