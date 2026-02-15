package io.contexa.contexaidentity.security.token.transport;

import io.contexa.contexacommon.properties.AuthContextProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseCookie;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CookieTokenStrategy extends AbstractTokenTransportStrategy implements TokenTransportStrategy {

    public CookieTokenStrategy(AuthContextProperties props) {
        super(props);
    }

    @Override
    public String resolveAccessToken(HttpServletRequest request) {
        return extractCookie(request, ACCESS_TOKEN_COOKIE_NAME);
    }

    @Override
    public String resolveRefreshToken(HttpServletRequest request) {
        return extractCookie(request, REFRESH_TOKEN_COOKIE_NAME);
    }

    @Override
    public TokenTransportResult prepareTokensForWrite(String accessToken, String refreshToken) {
        List<ResponseCookie> cookiesToSet = new ArrayList<>();

        if (StringUtils.hasText(accessToken)) {
            ResponseCookie accessCookie = ResponseCookie.from(ACCESS_TOKEN_COOKIE_NAME, accessToken)
                    .path(DEFAULT_COOKIE_PATH)
                    .httpOnly(HTTP_ONLY)
                    .secure(cookieSecureFlag)
                    .sameSite(SAME_SITE)
                    .maxAge((int) (accessTokenValidity / 1000))
                    .build();
            cookiesToSet.add(accessCookie);
        }

        if (StringUtils.hasText(refreshToken)) {
            ResponseCookie refreshCookie = ResponseCookie.from(REFRESH_TOKEN_COOKIE_NAME, refreshToken)
                    .path(DEFAULT_COOKIE_PATH)
                    .httpOnly(HTTP_ONLY)
                    .secure(cookieSecureFlag)
                    .sameSite(SAME_SITE)
                    .maxAge((int) (refreshTokenValidity / 1000))
                    .build();
            cookiesToSet.add(refreshCookie);
        }

        Map<String, Object> body = new HashMap<>();
        body.put("status", "SUCCESS");
        body.put("message", "Authentication successful");
        body.put("tokenTransportMethod", "COOKIE");

        return TokenTransportResult.builder()
                .body(body)
                .cookiesToSet(cookiesToSet)
                .build();
    }

    @Override
    public TokenTransportResult prepareTokensForClear() {
        List<ResponseCookie> cookiesToRemove = new ArrayList<>();

        ResponseCookie expiredAccessCookie = ResponseCookie.from(ACCESS_TOKEN_COOKIE_NAME, "")
                .path(DEFAULT_COOKIE_PATH)
                .httpOnly(HTTP_ONLY)
                .secure(cookieSecureFlag)
                .sameSite(SAME_SITE)
                .maxAge(0)
                .build();
        cookiesToRemove.add(expiredAccessCookie);

        ResponseCookie expiredRefreshCookie = ResponseCookie.from(REFRESH_TOKEN_COOKIE_NAME, "")
                .path(DEFAULT_COOKIE_PATH)
                .httpOnly(HTTP_ONLY)
                .secure(cookieSecureFlag)
                .sameSite(SAME_SITE)
                .maxAge(0)
                .build();
        cookiesToRemove.add(expiredRefreshCookie);

        return TokenTransportResult.builder()
                .cookiesToRemove(cookiesToRemove)
                .body(Map.of("message", "Tokens cleared successfully", "tokenTransportMethod", "COOKIE"))
                .build();
    }
}

