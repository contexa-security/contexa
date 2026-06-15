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
package io.contexa.contexaidentity.security.token.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.token.dto.TokenPair;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.token.transport.TokenTransportStrategy;
import io.contexa.contexaidentity.security.token.validator.TokenValidator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OAuth2TokenServiceTest {

    private OAuth2TokenService service;

    @Mock
    private OAuth2AuthorizedClientManager authorizedClientManager;

    @Mock
    private ClientRegistrationRepository clientRegistrationRepository;

    @Mock
    private OAuth2AuthorizationService authorizationService;

    @Mock
    private TokenValidator tokenValidator;

    @Mock
    private AuthContextProperties properties;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private TokenTransportStrategy transportStrategy;

    @Mock
    private Authentication authentication;

    @BeforeEach
    void setUp() {
        service = new OAuth2TokenService(
                authorizedClientManager,
                clientRegistrationRepository,
                authorizationService,
                tokenValidator,
                properties,
                objectMapper,
                transportStrategy
        );
        when(authentication.getName()).thenReturn("testUser");
    }

    @Test
    @DisplayName("Constructor should throw exception when any parameter is null")
    void constructorThrowsExceptionOnNullParameter() {
        assertThatThrownBy(() -> new OAuth2TokenService(null, clientRegistrationRepository, authorizationService, tokenValidator, properties, objectMapper, transportStrategy))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("createTokenPair should return TokenPair when authorization is successful")
    void createTokenPairSuccess() {
        OAuth2AuthorizedClient authorizedClient = mock(OAuth2AuthorizedClient.class);
        OAuth2AccessToken accessToken = mock(OAuth2AccessToken.class);
        OAuth2RefreshToken refreshToken = mock(OAuth2RefreshToken.class);

        when(authorizedClient.getAccessToken()).thenReturn(accessToken);
        when(authorizedClient.getRefreshToken()).thenReturn(refreshToken);
        when(accessToken.getTokenValue()).thenReturn("access-token-123");
        when(accessToken.getExpiresAt()).thenReturn(Instant.now().plusSeconds(3600));
        when(accessToken.getScopes()).thenReturn(Collections.singleton("read"));
        when(refreshToken.getTokenValue()).thenReturn("refresh-token-123");
        when(refreshToken.getExpiresAt()).thenReturn(Instant.now().plusSeconds(7200));

        when(authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class))).thenReturn(authorizedClient);

        TokenPair tokenPair = service.createTokenPair(authentication, "device-123");

        assertThat(tokenPair).isNotNull();
        assertThat(tokenPair.getAccessToken()).isEqualTo("access-token-123");
        assertThat(tokenPair.getRefreshToken()).isEqualTo("refresh-token-123");
    }

    @Test
    @DisplayName("createTokenPair should throw OAuth2AuthenticationException when authorization client is null")
    void createTokenPairThrowsExceptionOnNullClient() {
        when(authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class))).thenReturn(null);

        assertThatThrownBy(() -> service.createTokenPair(authentication, "device-123"))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .hasMessageContaining("Failed to authorize client");
    }

    @Test
    @DisplayName("refresh should throw exception when authorization not found")
    void refreshThrowsExceptionOnNullAuthorization() {
        when(authorizationService.findByToken(any(), any())).thenReturn(null);

        assertThatThrownBy(() -> service.refresh("refresh-token-123"))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .hasMessageContaining("Authorization not found");
    }

    @Test
    @DisplayName("refresh should throw exception when refresh token is invalidated")
    @SuppressWarnings("unchecked")
    void refreshThrowsExceptionOnInvalidatedToken() {
        OAuth2Authorization authorization = mock(OAuth2Authorization.class);
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshTokenMeta = mock(OAuth2Authorization.Token.class);

        when(authorizationService.findByToken("refresh-token-123", OAuth2TokenType.REFRESH_TOKEN)).thenReturn(authorization);
        when(authorization.getRefreshToken()).thenReturn(refreshTokenMeta);
        when(refreshTokenMeta.isInvalidated()).thenReturn(true);

        assertThatThrownBy(() -> service.refresh("refresh-token-123"))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .hasMessageContaining("Refresh token is invalidated");
    }

    @Test
    @DisplayName("refresh should throw exception when refresh token is expired")
    @SuppressWarnings("unchecked")
    void refreshThrowsExceptionOnExpiredToken() {
        OAuth2Authorization authorization = mock(OAuth2Authorization.class);
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshTokenMeta = mock(OAuth2Authorization.Token.class);

        when(authorizationService.findByToken("refresh-token-123", OAuth2TokenType.REFRESH_TOKEN)).thenReturn(authorization);
        when(authorization.getRefreshToken()).thenReturn(refreshTokenMeta);
        when(refreshTokenMeta.isInvalidated()).thenReturn(false);
        when(refreshTokenMeta.isExpired()).thenReturn(true);

        assertThatThrownBy(() -> service.refresh("refresh-token-123"))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .hasMessageContaining("Refresh token is expired");
    }

    @Test
    @DisplayName("refresh should return refreshed tokens on success")
    @SuppressWarnings("unchecked")
    void refreshSuccess() {
        OAuth2Authorization authorization = mock(OAuth2Authorization.class);
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshTokenMeta = mock(OAuth2Authorization.Token.class);

        when(authorizationService.findByToken("refresh-token-123", OAuth2TokenType.REFRESH_TOKEN)).thenReturn(authorization);
        when(authorization.getRefreshToken()).thenReturn(refreshTokenMeta);
        when(refreshTokenMeta.isInvalidated()).thenReturn(false);
        when(refreshTokenMeta.isExpired()).thenReturn(false);
        when(authorization.getPrincipalName()).thenReturn("testUser");
        when(authorization.getAuthorizedScopes()).thenReturn(Collections.singleton("read"));

        ClientRegistration clientRegistration = mock(ClientRegistration.class);
        when(clientRegistrationRepository.findByRegistrationId("aidc-internal")).thenReturn(clientRegistration);

        OAuth2AuthorizedClient refreshedClient = mock(OAuth2AuthorizedClient.class);
        OAuth2AccessToken accessToken = mock(OAuth2AccessToken.class);
        OAuth2RefreshToken newRefreshToken = mock(OAuth2RefreshToken.class);

        when(refreshedClient.getAccessToken()).thenReturn(accessToken);
        when(refreshedClient.getRefreshToken()).thenReturn(newRefreshToken);
        when(accessToken.getTokenValue()).thenReturn("new-access-token");
        when(newRefreshToken.getTokenValue()).thenReturn("new-refresh-token");

        when(authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class))).thenReturn(refreshedClient);

        TokenService.RefreshResult result = service.refresh("refresh-token-123");

        assertThat(result).isNotNull();
        assertThat(result.accessToken()).isEqualTo("new-access-token");
        assertThat(result.refreshToken()).isEqualTo("new-refresh-token");
    }

    @Test
    @DisplayName("Delegating methods should delegate to tokenValidator")
    void delegatingMethodsDelegateToValidator() {
        when(tokenValidator.validateAccessToken("token")).thenReturn(true);
        assertThat(service.validateAccessToken("token")).isTrue();
        verify(tokenValidator).validateAccessToken("token");

        when(tokenValidator.validateRefreshToken("token")).thenReturn(true);
        assertThat(service.validateRefreshToken("token")).isTrue();
        verify(tokenValidator).validateRefreshToken("token");

        service.invalidateRefreshToken("token");
        verify(tokenValidator).invalidateRefreshToken("token");

        Authentication mockAuth = mock(Authentication.class);
        when(tokenValidator.getAuthentication("token")).thenReturn(mockAuth);
        assertThat(service.getAuthentication("token")).isEqualTo(mockAuth);
        verify(tokenValidator).getAuthentication("token");

        when(tokenValidator.shouldRotateRefreshToken("token")).thenReturn(true);
        assertThat(service.shouldRotateRefreshToken("token")).isTrue();
        verify(tokenValidator).shouldRotateRefreshToken("token");
    }

    @Test
    @DisplayName("Transport delegating methods should delegate to transportStrategy")
    void transportDelegatingMethodsDelegate() {
        TokenTransportResult mockResult = TokenTransportResult.builder().build();
        when(transportStrategy.prepareTokensForWrite("access", "refresh")).thenReturn(mockResult);
        assertThat(service.prepareTokensForTransport("access", "refresh")).isEqualTo(mockResult);
        verify(transportStrategy).prepareTokensForWrite("access", "refresh");

        when(transportStrategy.prepareTokensForClear()).thenReturn(mockResult);
        assertThat(service.prepareClearTokens()).isEqualTo(mockResult);
        verify(transportStrategy).prepareTokensForClear();

        HttpServletRequest req = mock(HttpServletRequest.class);
        when(transportStrategy.resolveAccessToken(req)).thenReturn("access");
        assertThat(service.resolveAccessToken(req)).isEqualTo("access");
        verify(transportStrategy).resolveAccessToken(req);

        when(transportStrategy.resolveRefreshToken(req)).thenReturn("refresh");
        assertThat(service.resolveRefreshToken(req)).isEqualTo("refresh");
        verify(transportStrategy).resolveRefreshToken(req);
    }
}
