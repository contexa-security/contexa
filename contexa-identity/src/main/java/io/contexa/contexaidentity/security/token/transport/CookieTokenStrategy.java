package io.contexa.contexaidentity.security.token.transport;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.token.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseCookie;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.contexa.contexaidentity.security.token.service.TokenService.ACCESS_TOKEN;
import static io.contexa.contexaidentity.security.token.service.TokenService.REFRESH_TOKEN;


public class CookieTokenStrategy extends AbstractTokenTransportStrategy implements TokenTransportStrategy {

    private static final String COOKIE_PATH = "/";

    public CookieTokenStrategy(AuthContextProperties props) {
        super(props);
    }

    @Override
    public String resolveAccessToken(HttpServletRequest request) {
        return extractCookie(request, ACCESS_TOKEN);
    }

    @Override
    public String resolveRefreshToken(HttpServletRequest request) {
        return extractCookie(request, REFRESH_TOKEN);
    }

    @Override
    public TokenTransportResult prepareTokensForWrite(String accessToken, String refreshToken,
                                                      TokenService.TokenServicePropertiesProvider propsProvider) {
        List<ResponseCookie> cookiesToSet = new ArrayList<>();

        
        if (StringUtils.hasText(accessToken)) {
            ResponseCookie accessCookie = ResponseCookie.from(propsProvider.getAccessTokenCookieName(), accessToken)
                    .path(propsProvider.getCookiePath())
                    .httpOnly(HTTP_ONLY)
                    .secure(propsProvider.isCookieSecure())
                    .sameSite(SAME_SITE)
                    .maxAge((int) propsProvider.getAccessTokenValidity() / 1000)
                    .build();
            cookiesToSet.add(accessCookie);
        }

        
        if (StringUtils.hasText(refreshToken)) {
            ResponseCookie refreshCookie = ResponseCookie.from(propsProvider.getRefreshTokenCookieName(), refreshToken)
                    .path(propsProvider.getCookiePath())
                    .httpOnly(HTTP_ONLY)
                    .secure(propsProvider.isCookieSecure())
                    .sameSite(SAME_SITE)
                    .maxAge((int) propsProvider.getRefreshTokenValidity() / 1000)
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
    public TokenTransportResult prepareTokensForClear(TokenService.TokenServicePropertiesProvider propsProvider) {
        List<ResponseCookie> cookiesToRemove = new ArrayList<>();

        
        ResponseCookie expiredAccessCookie = ResponseCookie.from(propsProvider.getAccessTokenCookieName(), "")
                .path(propsProvider.getCookiePath())
                .httpOnly(HTTP_ONLY)
                .secure(propsProvider.isCookieSecure())
                .sameSite(SAME_SITE)
                .maxAge(0)
                .build();
        cookiesToRemove.add(expiredAccessCookie);

        
        ResponseCookie expiredRefreshCookie = ResponseCookie.from(propsProvider.getRefreshTokenCookieName(), "")
                .path(propsProvider.getCookiePath())
                .httpOnly(HTTP_ONLY)
                .secure(propsProvider.isCookieSecure())
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



