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
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.security.session.SessionIdResolver;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.DeviceAwareOAuth2AuthorizationService;
import io.contexa.contexaidentity.security.handler.logout.CompositeLogoutHandler;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineService;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A sign-out that carries only the access token, as the HEADER transport sends it, ends the sign-in that token belongs
 * to: the access token and its refresh token. A token that is not a live one of this server changes nothing, and the
 * sign-out is answered as before.
 */
class SignOutWithTheAccessTokenAloneTest {

    private final InMemoryOAuth2AuthorizationService stored = new InMemoryOAuth2AuthorizationService();
    private final TokenService tokens = mock(TokenService.class);
    private DeviceAwareOAuth2AuthorizationService authorizations;
    private CompositeLogoutHandler signOut;
    private RegisteredClient client;

    @BeforeEach
    void setUp() {
        AuthContextProperties properties = new AuthContextProperties();
        authorizations = new DeviceAwareOAuth2AuthorizationService(stored, mock(JdbcTemplate.class), properties);
        IdentityOAuth2AutoConfiguration configuration = new IdentityOAuth2AutoConfiguration(
                new TransactionTemplate(mock(PlatformTransactionManager.class)), properties);
        StaticListableBeanFactory none = new StaticListableBeanFactory();
        signOut = configuration.compositeLogoutHandler(tokens, properties,
                none.getBeanProvider(ZeroTrustSecurityService.class), mock(SessionIdResolver.class), authorizations,
                none.getBeanProvider(MfaSessionRepository.class), none.getBeanProvider(MfaStateMachineService.class));
        when(tokens.prepareClearTokens()).thenReturn(TokenTransportResult.builder().build());
        when(tokens.resolveAccessToken(any())).thenAnswer(invocation -> bearer(invocation.getArgument(0)));
        client = RegisteredClient.withId("internal")
                .clientId("default-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .build();
    }

    @Test
    void theAccessTokenAloneEndsItsSignInAndItsRefreshToken() {
        signedIn("alice-login", "access-alice", Instant.now().plus(Duration.ofHours(1)));
        signedIn("alice-other", "access-alice-2", Instant.now().plus(Duration.ofHours(1)));

        signOut.logout(signOutWith("access-alice"), new MockHttpServletResponse(), null);

        OAuth2Authorization ended = stored.findById("alice-login");
        assertThat(ended.getAccessToken().isInvalidated()).isTrue();
        assertThat(ended.getRefreshToken().isInvalidated()).isTrue();
        OAuth2Authorization other = stored.findById("alice-other");
        assertThat(other.getAccessToken().isInvalidated()).isFalse();
        assertThat(other.getRefreshToken().isInvalidated()).isFalse();
    }

    @Test
    void aTokenOfNoLiveSignInChangesNothing() {
        signedIn("alice-login", "access-alice", Instant.now().plus(Duration.ofHours(1)));
        signedIn("bob-login", "access-bob", Instant.now().minus(Duration.ofMinutes(1)));

        signOut.logout(signOutWith("access-forged"), new MockHttpServletResponse(), null);
        signOut.logout(signOutWith("access-bob"), new MockHttpServletResponse(), null);

        assertThat(stored.findById("alice-login").getRefreshToken().isInvalidated()).isFalse();
        assertThat(stored.findById("bob-login").getRefreshToken().isInvalidated()).isFalse();
    }

    private void signedIn(String id, String accessToken, Instant accessExpiresAt) {
        Instant issuedAt = accessExpiresAt.minus(Duration.ofHours(2));
        stored.save(OAuth2Authorization.withRegisteredClient(client)
                .id(id)
                .principalName("alice")
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken, issuedAt,
                        accessExpiresAt))
                .refreshToken(new OAuth2RefreshToken("refresh-" + id, issuedAt, Instant.now().plus(Duration.ofDays(1))))
                .build());
    }

    private static MockHttpServletRequest signOutWith(String accessToken) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout");
        request.addHeader("Authorization", "Bearer " + accessToken);
        return request;
    }

    private static String bearer(MockHttpServletRequest request) {
        String header = request.getHeader("Authorization");
        return header != null && header.startsWith("Bearer ") ? header.substring(7) : null;
    }
}
