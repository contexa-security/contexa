package io.contexa.contexaidentity.security.handler;

import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.token.dto.TokenPair;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

import java.io.IOException;
import java.util.Map;

/**
 * OAuth2/JWT 토큰 기반 성공 핸들러의 추상 부모 클래스
 *
 * 토큰 생성, 전송 준비, 쿠키 설정 등의 공통 로직 제공
 * 하위 클래스에서 응답 데이터 구성 로직만 구현
 */
@Slf4j
public abstract class AbstractTokenBasedSuccessHandler implements PlatformAuthenticationSuccessHandler {

    protected final TokenService tokenService;
    protected final AuthResponseWriter responseWriter;
    protected final AuthContextProperties authContextProperties;

    private PlatformAuthenticationSuccessHandler delegateHandler;

    protected AbstractTokenBasedSuccessHandler(TokenService tokenService,
                                                AuthResponseWriter responseWriter,
                                                AuthContextProperties authContextProperties) {
        this.tokenService = tokenService;
        this.responseWriter = responseWriter;
        this.authContextProperties = authContextProperties;
    }

    /**
     * 사용자 커스텀 핸들러 설정
     *
     * @param delegateHandler 위임할 성공 핸들러
     */
    public void setDelegateHandler(@Nullable PlatformAuthenticationSuccessHandler delegateHandler) {
        this.delegateHandler = delegateHandler;
        if (delegateHandler != null) {
            log.info("Delegate success handler set: {}", delegateHandler.getClass().getName());
        }
    }

    /**
     * 토큰 생성 공통 로직
     *
     * @param authentication 인증 객체
     * @param deviceId 디바이스 ID (nullable)
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @return 생성된 토큰 쌍
     */
    protected TokenPair createTokenPair(Authentication authentication, String deviceId,
                                        HttpServletRequest request, HttpServletResponse response) {
        return tokenService.createTokenPair(authentication, deviceId, request, response);
    }

    /**
     * 토큰 전송 정보 준비 공통 로직
     *
     * @param accessToken Access Token
     * @param refreshToken Refresh Token
     * @return 토큰 전송 정보
     */
    protected TokenTransportResult prepareTokenTransport(String accessToken, String refreshToken) {
        return tokenService.prepareTokensForTransport(accessToken, refreshToken);
    }

    /**
     * 쿠키 설정 공통 로직
     *
     * @param response HTTP 응답
     * @param transportResult 토큰 전송 정보
     */
    protected void setCookies(HttpServletResponse response, TokenTransportResult transportResult) {
        if (transportResult != null && transportResult.getCookiesToSet() != null) {
            for (ResponseCookie cookie : transportResult.getCookiesToSet()) {
                response.addHeader("Set-Cookie", cookie.toString());
            }
        }
    }

    /**
     * JSON 응답 작성 공통 로직
     *
     * @param response HTTP 응답
     * @param responseData 응답 데이터
     * @throws IOException IO 예외
     */
    protected void writeJsonResponse(HttpServletResponse response, Map<String, Object> responseData) throws IOException {
        responseWriter.writeSuccessResponse(response, responseData, HttpServletResponse.SC_OK);
    }

    /**
     * 응답 데이터 구성 - 하위 클래스에서 구현
     *
     * @param transportResult 토큰 전송 정보
     * @param authentication 인증 객체
     * @param request HTTP 요청
     * @return 응답 데이터 Map
     */
    protected abstract Map<String, Object> buildResponseData(TokenTransportResult transportResult,
                                                              Authentication authentication,
                                                              HttpServletRequest request);

    /**
     * 리다이렉트 URL 결정 - 하위 클래스에서 필요시 오버라이드
     *
     * @param request HTTP 요청
     * @return 리다이렉트 URL
     */
    protected abstract String determineTargetUrl(HttpServletRequest request);

    /**
     * 위임 핸들러 실행 공통 로직
     *
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @param authentication 인증 객체
     * @param result 토큰 전송 결과
     * @return 위임 핸들러 실행 여부
     * @throws IOException IO 예외
     */
    protected final boolean executeDelegateHandler(HttpServletRequest request,
                                                    HttpServletResponse response,
                                                    Authentication authentication,
                                                    @Nullable TokenTransportResult result) throws IOException {
        if (delegateHandler != null && !response.isCommitted()) {
            try {
                delegateHandler.onAuthenticationSuccess(request, response, authentication, result);
                return true;
            } catch (Exception e) {
                log.error("Error in delegate success handler", e);
            }
        }
        return false;
    }

    /**
     * 클라이언트 IP 추출 공통 로직
     *
     * @param request HTTP 요청
     * @return 클라이언트 IP
     */
    protected String extractClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }
}
