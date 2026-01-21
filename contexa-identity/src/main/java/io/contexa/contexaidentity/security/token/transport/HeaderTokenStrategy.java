package io.contexa.contexaidentity.security.token.transport;

import io.contexa.contexacommon.properties.AuthContextProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

import static io.contexa.contexaidentity.security.token.service.TokenService.*;

public class HeaderTokenStrategy extends AbstractTokenTransportStrategy implements TokenTransportStrategy {

    public HeaderTokenStrategy(AuthContextProperties props) {
        super(props);
    }

    @Override
    public String resolveAccessToken(HttpServletRequest request) {
        String authHeader = request.getHeader(ACCESS_TOKEN_HEADER);
        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
            return authHeader.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    @Override
    public String resolveRefreshToken(HttpServletRequest request) {
        return request.getHeader(REFRESH_TOKEN_HEADER);
    }

    @Override
    public TokenTransportResult prepareTokensForWrite(String accessToken, String refreshToken,
                                                      TokenServicePropertiesProvider propsProvider) {
        Map<String, Object> body = new HashMap<>();

        body.put("accessToken", accessToken);
        body.put("tokenType", "Bearer");
        body.put("expiresIn", propsProvider.getAccessTokenValidity());

        if (StringUtils.hasText(refreshToken)) {
            body.put("refreshToken", refreshToken);
            body.put("refreshExpiresIn", propsProvider.getRefreshTokenValidity());
        }

        body.put("tokenTransportMethod", "HEADER");

        return TokenTransportResult.builder()
                .body(body)
                .build();
    }

    @Override
    public TokenTransportResult prepareTokensForClear(TokenServicePropertiesProvider propsProvider) {

        Map<String, Object> body = new HashMap<>();
        body.put("message", "Tokens have been invalidated. Please remove tokens from client storage.");
        body.put("tokenTransportMethod", "HEADER");
        body.put("action", "CLEAR_TOKENS");

        return TokenTransportResult.builder()
                .body(body)
                .build();
    }
}