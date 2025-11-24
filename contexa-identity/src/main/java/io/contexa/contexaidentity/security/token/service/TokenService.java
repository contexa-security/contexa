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

public interface TokenService extends TokenProvider, TokenValidator /* TokenTransportStrategy 상속 제거 */ {

    String ACCESS_TOKEN = "accessToken";
    String REFRESH_TOKEN = "refreshToken";
    String ACCESS_TOKEN_HEADER  = "Authorization";
    String REFRESH_TOKEN_HEADER = "X-Refresh-Token";
    String BEARER_PREFIX        = "Bearer ";

    AuthContextProperties properties();
    void blacklistRefreshToken(String refreshToken, String username, String reason);
    record RefreshResult(String accessToken, String refreshToken) {}
    ObjectMapper getObjectMapper(); // 아직 핸들러에서 사용 중이므로 유지

    /**
     * Access Token과 Refresh Token을 한 번에 생성
     *
     * <p><strong>권장 메소드:</strong> 중복 서버 호출을 방지하기 위해 이 메소드를 사용하세요.
     *
     * @param authentication 인증 정보
     * @param deviceId 디바이스 ID (nullable)
     * @return Access Token과 Refresh Token 쌍
     * @since 2025.01
     */
    default TokenPair createTokenPair(Authentication authentication, @Nullable String deviceId) {
        // 기본 구현: 레거시 메소드 사용 (하위 호환성)
        String accessToken = createAccessToken(authentication, deviceId);
        String refreshToken = properties().isEnableRefreshToken()
                ? createRefreshToken(authentication, deviceId)
                : null;

        return TokenPair.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    /**
     * Access Token과 Refresh Token을 한 번에 생성 (HttpServletRequest/Response 포함)
     *
     * <p>OAuth2TokenEndpointFilter를 직접 호출하기 위해 request/response가 필요한 경우 사용합니다.
     *
     * @param authentication 인증 정보
     * @param deviceId 디바이스 ID (nullable)
     * @param request HTTP 요청 (Filter 직접 호출용)
     * @param response HTTP 응답 (Filter 직접 호출용)
     * @return Access Token과 Refresh Token 쌍
     * @since 2025.01
     */
    default TokenPair createTokenPair(Authentication authentication, @Nullable String deviceId,
                                     HttpServletRequest request, HttpServletResponse response) {
        // 기본 구현: request/response 무시하고 일반 메소드 호출
        return createTokenPair(authentication, deviceId);
    }

    /**
     * 현재 TokenTransportStrategy에 따라 토큰들을 어떻게 전달할지에 대한 정보를 담은 객체를 반환합니다.
     * 이 객체는 HTTP 응답 헤더/쿠키 설정 정보 및 JSON 본문에 포함될 데이터를 포함할 수 있습니다.
     * 실제 응답 작성은 핸들러가 AuthResponseWriter를 통해 수행합니다.
     */
    TokenTransportResult prepareTokensForTransport(String accessToken, String refreshToken);

    /**
     * 현재 TokenTransportStrategy에 따라 토큰들을 클리어하기 위한 정보를 담은 객체를 반환합니다.
     */
    TokenTransportResult prepareClearTokens();

    String resolveAccessToken(HttpServletRequest request);
    String resolveRefreshToken(HttpServletRequest request);

    // TokenTransportStrategy를 내부에서만 사용하도록 하고 외부 노출 최소화
    TokenTransportStrategy getUnderlyingTokenTransportStrategy();

    interface TokenServicePropertiesProvider {
        long getAccessTokenValidity();
        long getRefreshTokenValidity();
        String getCookiePath(); // 예시
        boolean isCookieSecure();
        String getRefreshTokenCookieName();
        String getAccessTokenCookieName();
    }
}


