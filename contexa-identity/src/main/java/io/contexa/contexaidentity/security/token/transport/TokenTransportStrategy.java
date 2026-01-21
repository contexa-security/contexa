package io.contexa.contexaidentity.security.token.transport;

import io.contexa.contexaidentity.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;

public interface TokenTransportStrategy {

    String resolveAccessToken(HttpServletRequest request);
    String resolveRefreshToken(HttpServletRequest request);

    TokenTransportResult prepareTokensForWrite(String accessToken, String refreshToken, TokenService.TokenServicePropertiesProvider tokenServiceProperties);

    TokenTransportResult prepareTokensForClear(TokenService.TokenServicePropertiesProvider tokenServiceProperties);
}

