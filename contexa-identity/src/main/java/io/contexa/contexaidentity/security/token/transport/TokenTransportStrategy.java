package io.contexa.contexaidentity.security.token.transport;

import jakarta.servlet.http.HttpServletRequest;

public interface TokenTransportStrategy {

    String resolveAccessToken(HttpServletRequest request);
    String resolveRefreshToken(HttpServletRequest request);

    TokenTransportResult prepareTokensForWrite(String accessToken, String refreshToken);

    TokenTransportResult prepareTokensForClear();
}

