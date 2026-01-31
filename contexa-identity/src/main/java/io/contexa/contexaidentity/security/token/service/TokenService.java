package io.contexa.contexaidentity.security.token.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.token.dto.TokenPair;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.token.transport.TokenTransportStrategy;
import io.contexa.contexaidentity.security.token.validator.TokenValidator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

public interface TokenService extends TokenProvider, TokenValidator  {

    String ACCESS_TOKEN = "accessToken";
    String REFRESH_TOKEN = "refreshToken";
    String ACCESS_TOKEN_HEADER  = "Authorization";
    String REFRESH_TOKEN_HEADER = "X-Refresh-Token";
    String BEARER_PREFIX        = "Bearer ";

    AuthContextProperties properties();
    void blacklistRefreshToken(String refreshToken, String username, String reason);
    record RefreshResult(String accessToken, String refreshToken) {}
    ObjectMapper getObjectMapper(); 

    default TokenPair createTokenPair(Authentication authentication, @Nullable String deviceId) {
        
        String accessToken = createAccessToken(authentication, deviceId);
        String refreshToken = properties().isEnableRefreshToken()
                ? createRefreshToken(authentication, deviceId)
                : null;

        return TokenPair.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    default TokenPair createTokenPair(Authentication authentication, @Nullable String deviceId,
                                     HttpServletRequest request, HttpServletResponse response) {
        return createTokenPair(authentication, deviceId);
    }

    TokenTransportResult prepareTokensForTransport(String accessToken, String refreshToken);
    TokenTransportResult prepareClearTokens();
    String resolveAccessToken(HttpServletRequest request);
    String resolveRefreshToken(HttpServletRequest request);

    interface TokenServicePropertiesProvider {
        long getAccessTokenValidity();
        long getRefreshTokenValidity();
        String getCookiePath(); 
        boolean isCookieSecure();
        String getRefreshTokenCookieName();
        String getAccessTokenCookieName();
    }
}

