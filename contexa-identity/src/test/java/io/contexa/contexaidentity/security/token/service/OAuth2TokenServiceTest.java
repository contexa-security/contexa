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
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
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
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
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
import static org.mockito.Mockito.never;
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
    @DisplayName("refresh should hand the presented refresh token to the Spring refresh provider")
    void refreshSuccess() {
        Instant issuedAt = Instant.now().minusSeconds(7200);
        OAuth2AccessToken storedAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                "stored-access-token", issuedAt, issuedAt.plusSeconds(3600));
        OAuth2RefreshToken presentedRefreshToken = new OAuth2RefreshToken(
                "refresh-token-123", issuedAt, issuedAt.plusSeconds(604800));
        stubActiveAuthorization(storedAccessToken, presentedRefreshToken);

        ClientRegistration clientRegistration = mock(ClientRegistration.class);
        when(clientRegistrationRepository.findByRegistrationId("aidc-internal")).thenReturn(clientRegistration);

        OAuth2AuthorizedClient refreshedClient = mock(OAuth2AuthorizedClient.class);
        OAuth2AccessToken accessToken = mock(OAuth2AccessToken.class);
        OAuth2RefreshToken newRefreshToken = mock(OAuth2RefreshToken.class);

        when(refreshedClient.getAccessToken()).thenReturn(accessToken);
        when(refreshedClient.getRefreshToken()).thenReturn(newRefreshToken);
        when(accessToken.getTokenValue()).thenReturn("new-access-token");
        when(newRefreshToken.getTokenValue()).thenReturn("new-refresh-token");

        ArgumentCaptor<OAuth2AuthorizeRequest> requestCaptor = ArgumentCaptor.forClass(OAuth2AuthorizeRequest.class);
        when(authorizedClientManager.authorize(requestCaptor.capture())).thenReturn(refreshedClient);

        TokenService.RefreshResult result = service.refresh("refresh-token-123");

        assertThat(result).isNotNull();
        assertThat(result.accessToken()).isEqualTo("new-access-token");
        assertThat(result.refreshToken()).isEqualTo("new-refresh-token");

        OAuth2AuthorizedClient handedOver = requestCaptor.getValue().getAuthorizedClient();
        assertThat(handedOver).isNotNull();
        assertThat(handedOver.getRefreshToken().getTokenValue()).isEqualTo("refresh-token-123");
        assertThat(handedOver.getAccessToken().getTokenValue()).isEqualTo("stored-access-token");
        assertThat(handedOver.getPrincipalName()).isEqualTo("testUser");
    }

    @Test
    @DisplayName("refresh should be refused when the authorization holds no access token")
    void refreshThrowsExceptionWithoutStoredAccessToken() {
        OAuth2Authorization authorization = mock(OAuth2Authorization.class);
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshTokenMeta = activeRefreshTokenMeta(
                new OAuth2RefreshToken("refresh-token-123", Instant.now(), Instant.now().plusSeconds(60)));
        when(authorizationService.findByToken("refresh-token-123", OAuth2TokenType.REFRESH_TOKEN)).thenReturn(authorization);
        when(authorization.getRefreshToken()).thenReturn(refreshTokenMeta);
        when(authorization.getAccessToken()).thenReturn(null);

        assertThatThrownBy(() -> service.refresh("refresh-token-123"))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .hasMessageContaining("Authorization has no access token");
    }

    @ParameterizedTest
    @EnumSource(value = ZeroTrustAction.class, names = {"BLOCK", "ESCALATE"})
    @DisplayName("refresh should be refused while zero trust blocks or escalates the user")
    void refreshRefusedWhenZeroTrustDenies(ZeroTrustAction action) {
        stubActiveAuthorization(
                new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "a", Instant.now(), Instant.now().plusSeconds(60)),
                new OAuth2RefreshToken("refresh-token-123", Instant.now(), Instant.now().plusSeconds(60)));
        ZeroTrustActionRepository actionRepository = mock(ZeroTrustActionRepository.class);
        when(actionRepository.getCurrentAction("testUser")).thenReturn(action);
        service.setZeroTrustActionRepository(actionRepository);

        assertThatThrownBy(() -> service.refresh("refresh-token-123"))
                .isInstanceOfSatisfying(OAuth2AuthenticationException.class, ex ->
                        assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.ACCESS_DENIED));
        verify(authorizedClientManager, never()).authorize(any());
    }

    @Test
    @DisplayName("refresh should require the MFA challenge while zero trust challenges the user")
    void refreshRequiresChallengeWhenZeroTrustChallenges() {
        stubActiveAuthorization(
                new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "a", Instant.now(), Instant.now().plusSeconds(60)),
                new OAuth2RefreshToken("refresh-token-123", Instant.now(), Instant.now().plusSeconds(60)));
        ZeroTrustActionRepository actionRepository = mock(ZeroTrustActionRepository.class);
        when(actionRepository.getCurrentAction("testUser")).thenReturn(ZeroTrustAction.CHALLENGE);
        service.setZeroTrustActionRepository(actionRepository);

        assertThatThrownBy(() -> service.refresh("refresh-token-123"))
                .isInstanceOfSatisfying(OAuth2AuthenticationException.class, ex ->
                        assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2TokenService.MFA_CHALLENGE_REQUIRED_ERROR));
        verify(authorizedClientManager, never()).authorize(any());
    }

    @SuppressWarnings("unchecked")
    private void stubActiveAuthorization(OAuth2AccessToken accessToken, OAuth2RefreshToken refreshToken) {
        OAuth2Authorization authorization = mock(OAuth2Authorization.class);
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshTokenMeta = activeRefreshTokenMeta(refreshToken);
        OAuth2Authorization.Token<OAuth2AccessToken> accessTokenMeta = mock(OAuth2Authorization.Token.class);
        when(accessTokenMeta.getToken()).thenReturn(accessToken);

        when(authorizationService.findByToken(refreshToken.getTokenValue(), OAuth2TokenType.REFRESH_TOKEN)).thenReturn(authorization);
        when(authorization.getRefreshToken()).thenReturn(refreshTokenMeta);
        when(authorization.getAccessToken()).thenReturn(accessTokenMeta);
        when(authorization.getPrincipalName()).thenReturn("testUser");
        when(authorization.getAuthorizedScopes()).thenReturn(Collections.singleton("read"));
    }

    @SuppressWarnings("unchecked")
    private OAuth2Authorization.Token<OAuth2RefreshToken> activeRefreshTokenMeta(OAuth2RefreshToken refreshToken) {
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshTokenMeta = mock(OAuth2Authorization.Token.class);
        when(refreshTokenMeta.isInvalidated()).thenReturn(false);
        when(refreshTokenMeta.isExpired()).thenReturn(false);
        when(refreshTokenMeta.getToken()).thenReturn(refreshToken);
        return refreshTokenMeta;
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
