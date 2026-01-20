package io.contexa.contexaidentity.security.token.transport;

import io.contexa.contexacommon.properties.AuthContextProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseCookie;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.contexa.contexaidentity.security.token.service.TokenService.*;

public class HeaderCookieTokenStrategy extends AbstractTokenTransportStrategy implements TokenTransportStrategy {

    private static final String COOKIE_PATH = "/";
    public HeaderCookieTokenStrategy(AuthContextProperties props) {
        super(props);
    }

    @Override
    public String resolveAccessToken(HttpServletRequest request) {
        String header = request.getHeader(ACCESS_TOKEN_HEADER);
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            return header.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    @Override
    public String resolveRefreshToken(HttpServletRequest request) {
        return extractCookie(request, REFRESH_TOKEN); 
    }

    @Override
    public TokenTransportResult prepareTokensForWrite(String accessToken, String refreshToken, TokenServicePropertiesProvider propsProvider) {
        Map<String, Object> body = new HashMap<>();
        body.put("accessToken", accessToken);
        body.put("tokenType", "Bearer");
        body.put("expiresIn", propsProvider.getAccessTokenValidity());
        body.put("tokenTransportMethod", "HEADER_COOKIE");

        List<ResponseCookie> cookiesToSet = new ArrayList<>();
        if (StringUtils.hasText(refreshToken)) {
            ResponseCookie refreshCookie = ResponseCookie.from(propsProvider.getRefreshTokenCookieName(), refreshToken)
                    .path(COOKIE_PATH) 
                    .httpOnly(HTTP_ONLY)
                    .secure(propsProvider.isCookieSecure())
                    .sameSite(SAME_SITE)
                    .maxAge((int) propsProvider.getRefreshTokenValidity() / 1000)
                    .build();
            cookiesToSet.add(refreshCookie);
            body.put("refreshExpiresIn", propsProvider.getRefreshTokenValidity());
        }

        return TokenTransportResult.builder()
                .body(body)
                .cookiesToSet(cookiesToSet)
                .build();
    }

    @Override
    public TokenTransportResult prepareTokensForClear(TokenServicePropertiesProvider propsProvider) {
        List<ResponseCookie> cookiesToRemove = new ArrayList<>();
        ResponseCookie expiredRefreshCookie = ResponseCookie.from(propsProvider.getRefreshTokenCookieName(), "")
                .path(COOKIE_PATH)
                .httpOnly(HTTP_ONLY)
                .secure(propsProvider.isCookieSecure())
                .sameSite(SAME_SITE)
                .maxAge(0)
                .build();
        cookiesToRemove.add(expiredRefreshCookie);

        return TokenTransportResult.builder()
                .cookiesToRemove(cookiesToRemove)
                .body(Map.of("message", "Tokens cleared by server instruction."))
                .build();
    }
}

