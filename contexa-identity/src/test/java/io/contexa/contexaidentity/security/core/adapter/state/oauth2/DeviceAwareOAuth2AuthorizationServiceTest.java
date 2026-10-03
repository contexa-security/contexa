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
package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import io.contexa.contexacommon.properties.AuthContextProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DeviceAwareOAuth2AuthorizationServiceTest {

    private static final RegisteredClient CLIENT = RegisteredClient.withId("internal-client-id")
            .clientId("internal-client")
            .clientSecret("{noop}secret")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .build();

    private final Map<String, OAuth2Authorization> stored = new HashMap<>();
    private OAuth2AuthorizationService delegate;
    private JdbcTemplate jdbcTemplate;
    private AuthContextProperties properties;
    private DeviceAwareOAuth2AuthorizationService service;

    @BeforeEach
    void setUp() {
        delegate = mock(OAuth2AuthorizationService.class);
        jdbcTemplate = mock(JdbcTemplate.class);
        properties = new AuthContextProperties();
        when(delegate.findById(anyString())).thenAnswer(invocation -> stored.get(invocation.<String>getArgument(0)));
        when(jdbcTemplate.queryForList(anyString(), eq(String.class), anyString()))
                .thenAnswer(invocation -> List.copyOf(stored.keySet()));
        service = new DeviceAwareOAuth2AuthorizationService(delegate, jdbcTemplate, properties);
    }

    @Test
    @DisplayName("A new login invalidates the earlier login when multiple logins are not allowed")
    void newLoginInvalidatesEarlierLogin() {
        properties.setAllowMultipleLogins(false);
        OAuth2Authorization first = authorization("first", "refresh-1", Instant.now().minusSeconds(60));
        stored.put(first.getId(), first);

        service.save(authorization("second", "refresh-2", Instant.now()));

        ArgumentCaptor<OAuth2Authorization> saved = ArgumentCaptor.forClass(OAuth2Authorization.class);
        verify(delegate, atLeastOnce()).save(saved.capture());
        assertThat(saved.getAllValues())
                .anySatisfy(authorization -> {
                    assertThat(authorization.getId()).isEqualTo("first");
                    assertThat(authorization.getRefreshToken().isInvalidated()).isTrue();
                });
    }

    @Test
    @DisplayName("Rotating the refresh token of an existing login does not count as a new login")
    void updateOfExistingAuthorizationSkipsLoginLimit() {
        properties.setAllowMultipleLogins(true);
        properties.setMaxConcurrentLogins(2);
        OAuth2Authorization deviceA = authorization("device-a", "refresh-a", Instant.now().minusSeconds(120));
        OAuth2Authorization deviceB = authorization("device-b", "refresh-b", Instant.now().minusSeconds(60));
        stored.put(deviceA.getId(), deviceA);
        stored.put(deviceB.getId(), deviceB);

        OAuth2Authorization rotatedB = authorization("device-b", "refresh-b-rotated", Instant.now());
        service.save(rotatedB);

        verify(jdbcTemplate, never()).queryForList(anyString(), eq(String.class), anyString());
        ArgumentCaptor<OAuth2Authorization> saved = ArgumentCaptor.forClass(OAuth2Authorization.class);
        verify(delegate).save(saved.capture());
        assertThat(saved.getValue()).isSameAs(rotatedB);
    }

    private static OAuth2Authorization authorization(String id, String refreshTokenValue, Instant issuedAt) {
        return OAuth2Authorization.withRegisteredClient(CLIENT)
                .id(id)
                .principalName("alice")
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                        "access-" + refreshTokenValue, issuedAt, issuedAt.plusSeconds(3600)))
                .refreshToken(new OAuth2RefreshToken(refreshTokenValue, issuedAt, issuedAt.plusSeconds(86400)))
                .build();
    }
}
