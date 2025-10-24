package io.contexa.contexaidentity.security.token.transport;

import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

import static io.contexa.contexaidentity.security.token.service.TokenService.*;

/**
 * 액세스 토큰과 리프레시 토큰을 모두 HTTP 헤더/JSON 본문으로 전송하는 전략
 *
 * 요청 시: Authorization 헤더와 X-Refresh-Token 헤더에서 토큰 추출
 * 응답 시: JSON 본문에 모든 토큰 정보 포함
 *
 * 주로 SPA(Single Page Application)나 모바일 앱에서 사용
 *
 * @since 2024.12
 */
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

        // 액세스 토큰 정보
        body.put("accessToken", accessToken);
        body.put("tokenType", "Bearer");
        body.put("expiresIn", propsProvider.getAccessTokenValidity());

        // 리프레시 토큰 정보
        if (StringUtils.hasText(refreshToken)) {
            body.put("refreshToken", refreshToken);
            body.put("refreshExpiresIn", propsProvider.getRefreshTokenValidity());
        }

        // 전송 방식 명시
        body.put("tokenTransportMethod", "HEADER");

        // 헤더 전용 전략이므로 쿠키는 설정하지 않음
        return TokenTransportResult.builder()
                .body(body)
                .build();
    }

    @Override
    public TokenTransportResult prepareTokensForClear(TokenServicePropertiesProvider propsProvider) {
        // 헤더 방식에서는 클라이언트가 토큰을 직접 관리하므로
        // 서버는 토큰이 무효화되었음을 알리는 메시지만 전송
        Map<String, Object> body = new HashMap<>();
        body.put("message", "Tokens have been invalidated. Please remove tokens from client storage.");
        body.put("tokenTransportMethod", "HEADER");
        body.put("action", "CLEAR_TOKENS");

        return TokenTransportResult.builder()
                .body(body)
                .build();
    }
}