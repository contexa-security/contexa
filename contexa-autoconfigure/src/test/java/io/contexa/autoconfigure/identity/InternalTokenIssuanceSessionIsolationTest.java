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

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationToken;
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
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class InternalTokenIssuanceSessionIsolationTest {

    private static final String CLIENT_SECRET = "isolation-test-secret";

    private OAuth2AuthorizedClientManager manager;
    private MockHttpSession browserSession;

    @BeforeEach
    void setUp() {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setClientSecret(CLIENT_SECRET);
        IdentityOAuth2AutoConfiguration configuration =
                new IdentityOAuth2AutoConfiguration(mock(TransactionTemplate.class), properties);

        RegisteredClient registeredClient = RegisteredClient.withId("internal-client-id")
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

        FilterChainProxy filterChainProxy = new FilterChainProxy(new DefaultSecurityFilterChain(
                AnyRequestMatcher.INSTANCE, new FakeOAuth2TokenEndpointFilter(registeredClient)));
        @SuppressWarnings("unchecked")
        ObjectProvider<FilterChainProxy> filterChainProxyProvider = mock(ObjectProvider.class);
        when(filterChainProxyProvider.getIfAvailable()).thenReturn(filterChainProxy);

        manager = configuration.authorizedClientManager(
                clientRegistrationRepository,
                filterChainProxyProvider,
                registeredClientRepository,
                mock(OAuth2AuthorizationService.class));
        browserSession = new MockHttpSession();
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("A second user logging in through the same browser session receives a token of their own")
    void secondUserInSameSessionGetsOwnToken() {
        OAuth2AuthorizedClient alice = issue("alice");
        OAuth2AuthorizedClient bob = issue("bob");

        assertThat(alice.getAccessToken().getTokenValue()).startsWith("access-alice-");
        assertThat(bob.getPrincipalName()).isEqualTo("bob");
        assertThat(bob.getAccessToken().getTokenValue()).startsWith("access-bob-");
    }

    @Test
    @DisplayName("Logging in again through the same browser session issues a new token")
    void reLoginInSameSessionIssuesNewToken() {
        OAuth2AuthorizedClient first = issue("alice");
        OAuth2AuthorizedClient second = issue("alice");

        assertThat(second.getAccessToken().getTokenValue())
                .isNotEqualTo(first.getAccessToken().getTokenValue());
    }

    @Test
    @DisplayName("Issued tokens are not kept in the HTTP session")
    void issuedTokensAreNotKeptInSession() {
        issue("alice");

        assertThat(browserSession.getAttributeNames().hasMoreElements()).isFalse();
    }

    private OAuth2AuthorizedClient issue(String username) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        request.setSession(browserSession);
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication principal = UsernamePasswordAuthenticationToken.authenticated(username, null, List.of());

        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                .withClientRegistrationId("aidc-internal")
                .principal(principal)
                .attribute(HttpServletRequest.class.getName(), request)
                .attribute(HttpServletResponse.class.getName(), response)
                .build();
        return manager.authorize(authorizeRequest);
    }

    /**
     * Stands in for the Spring Authorization Server token endpoint: the token client locates it by
     * class name and reads the issued token from the security context, as the real success handler leaves it.
     */
    static final class FakeOAuth2TokenEndpointFilter extends OncePerRequestFilter {

        private final RegisteredClient registeredClient;
        private final AtomicInteger sequence = new AtomicInteger();

        FakeOAuth2TokenEndpointFilter(RegisteredClient registeredClient) {
            this.registeredClient = registeredClient;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
            Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
            Instant issuedAt = Instant.now();
            int number = sequence.incrementAndGet();
            OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                    "access-" + request.getParameter("username") + "-" + number,
                    issuedAt, issuedAt.plus(1, ChronoUnit.HOURS));
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                    "refresh-" + request.getParameter("username") + "-" + number,
                    issuedAt, issuedAt.plus(7, ChronoUnit.DAYS));
            SecurityContextHolder.getContext().setAuthentication(new OAuth2AccessTokenAuthenticationToken(
                    registeredClient, clientPrincipal, accessToken, refreshToken));
        }
    }
}
