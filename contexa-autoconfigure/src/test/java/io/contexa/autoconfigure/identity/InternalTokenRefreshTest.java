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
package io.contexa.autoconfigure.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationToken;
import io.contexa.contexaidentity.security.token.service.OAuth2TokenService;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.validator.TokenValidator;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class InternalTokenRefreshTest {

    private static final String CLIENT_SECRET = "refresh-test-secret";

    private FakeOAuth2TokenEndpointFilter tokenEndpoint;
    private OAuth2AuthorizationService authorizationService;
    private RegisteredClient registeredClient;
    private OAuth2TokenService tokenService;

    @BeforeEach
    void setUp() {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setClientSecret(CLIENT_SECRET);
        IdentityOAuth2AutoConfiguration configuration =
                new IdentityOAuth2AutoConfiguration(mock(TransactionTemplate.class), properties);

        registeredClient = RegisteredClient.withId("internal-client-id")
                .clientId(properties.getOauth2().getClientId())
                .clientSecret("{noop}" + CLIENT_SECRET)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("read")
                .build();
        RegisteredClientRepository registeredClientRepository = new InMemoryRegisteredClientRepository(registeredClient);
        ClientRegistrationRepository clientRegistrationRepository =
                configuration.clientRegistrationRepository(registeredClientRepository);

        tokenEndpoint = new FakeOAuth2TokenEndpointFilter(registeredClient);
        FilterChainProxy filterChainProxy = new FilterChainProxy(
                new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE, tokenEndpoint));
        @SuppressWarnings("unchecked")
        ObjectProvider<FilterChainProxy> filterChainProxyProvider = mock(ObjectProvider.class);
        when(filterChainProxyProvider.getIfAvailable()).thenReturn(filterChainProxy);
        when(filterChainProxyProvider.getObject()).thenReturn(filterChainProxy);

        authorizationService = mock(OAuth2AuthorizationService.class);
        OAuth2AuthorizedClientManager manager = configuration.authorizedClientManager(
                clientRegistrationRepository, filterChainProxyProvider, registeredClientRepository, authorizationService);

        tokenService = new OAuth2TokenService(manager, clientRegistrationRepository, authorizationService,
                mock(TokenValidator.class), properties, new ObjectMapper(), null);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/refresh");
        request.setQueryString("scope=admin&grant_type=password");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, new MockHttpServletResponse()));
    }

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("An expired access token is renewed through the refresh_token grant with the presented refresh token")
    void presentedRefreshTokenReachesTheTokenEndpoint() {
        storeAuthorization("refresh-alice", Instant.now().minus(2, ChronoUnit.HOURS));

        TokenService.RefreshResult result = tokenService.refresh("refresh-alice");

        assertThat(tokenEndpoint.lastGrantType).isEqualTo("refresh_token");
        assertThat(tokenEndpoint.lastRefreshToken).isEqualTo("refresh-alice");
        assertThat(tokenEndpoint.lastQueryString).isNull();
        assertThat(result.accessToken()).startsWith("access-refreshed-");
        assertThat(result.refreshToken()).startsWith("refresh-rotated-");
    }

    @Test
    @DisplayName("An access token that is still valid is returned as is, following the Spring refresh rule")
    void validAccessTokenIsKept() {
        storeAuthorization("refresh-alice", Instant.now());

        TokenService.RefreshResult result = tokenService.refresh("refresh-alice");

        assertThat(tokenEndpoint.calls.get()).isZero();
        assertThat(result.accessToken()).isEqualTo("stored-access-refresh-alice");
        assertThat(result.refreshToken()).isEqualTo("refresh-alice");
    }

    @Test
    @DisplayName("The error of the token endpoint reaches the caller with its OAuth2 error code")
    void tokenEndpointErrorIsPropagated() {
        storeAuthorization("revoked", Instant.now().minus(2, ChronoUnit.HOURS));

        assertThatThrownBy(() -> tokenService.refresh("revoked"))
                .isInstanceOfSatisfying(OAuth2AuthorizationException.class, ex ->
                        assertThat(ex.getError().getErrorCode()).isEqualTo("invalid_grant"));
    }

    private void storeAuthorization(String refreshTokenValue, Instant issuedAt) {
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id("authorization-" + refreshTokenValue)
                .principalName("alice")
                .authorizationGrantType(AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER)
                .authorizedScopes(Set.of("read"))
                .accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                        "stored-access-" + refreshTokenValue, issuedAt, issuedAt.plus(1, ChronoUnit.HOURS)))
                .refreshToken(new OAuth2RefreshToken(refreshTokenValue, issuedAt, issuedAt.plus(7, ChronoUnit.DAYS)))
                .build();
        when(authorizationService.findByToken(refreshTokenValue, OAuth2TokenType.REFRESH_TOKEN)).thenReturn(authorization);
    }

    /**
     * Stands in for the Spring Authorization Server token endpoint and answers the refresh_token grant.
     */
    static final class FakeOAuth2TokenEndpointFilter extends OncePerRequestFilter {

        private final RegisteredClient registeredClient;
        private final AtomicInteger calls = new AtomicInteger();
        private volatile String lastGrantType;
        private volatile String lastRefreshToken;
        private volatile String lastQueryString;

        FakeOAuth2TokenEndpointFilter(RegisteredClient registeredClient) {
            this.registeredClient = registeredClient;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws IOException {
            int number = calls.incrementAndGet();
            lastGrantType = request.getParameter("grant_type");
            lastRefreshToken = request.getParameter("refresh_token");
            lastQueryString = request.getQueryString();
            if ("revoked".equals(lastRefreshToken)) {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.setContentType("application/json");
                response.getOutputStream().write("{\"error\":\"invalid_grant\"}".getBytes(StandardCharsets.UTF_8));
                return;
            }
            Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
            Instant issuedAt = Instant.now();
            OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                    "access-refreshed-" + number, issuedAt, issuedAt.plus(1, ChronoUnit.HOURS));
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                    "refresh-rotated-" + number, issuedAt, issuedAt.plus(7, ChronoUnit.DAYS));
            SecurityContextHolder.getContext().setAuthentication(new OAuth2AccessTokenAuthenticationToken(
                    registeredClient, clientPrincipal, accessToken, refreshToken));
        }
    }
}
