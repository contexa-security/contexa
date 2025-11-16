package io.contexa.contexaidentity.security.handler;

import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

/**
 * 세션 기반 실패 핸들러의 추상 부모 클래스
 *
 * API vs 일반 요청 판단, 리다이렉트 URL 생성 등의 공통 로직 제공
 * Spring Security의 SimpleUrlAuthenticationFailureHandler 참고
 */
@Slf4j
public abstract class SessionBasedFailureHandler implements PlatformAuthenticationFailureHandler {

    protected final AuthResponseWriter responseWriter;

    protected SessionBasedFailureHandler(AuthResponseWriter responseWriter) {
        this.responseWriter = responseWriter;
    }

    /**
     * API 요청 여부 판단 공통 로직
     *
     * @param request HTTP 요청
     * @return API 요청이면 true
     */
    protected boolean isApiRequest(HttpServletRequest request) {
        String acceptHeader = request.getHeader("Accept");
        if (acceptHeader != null && acceptHeader.contains("application/json")) {
            return true;
        }

        String contentType = request.getContentType();
        if (contentType != null && contentType.contains("application/json")) {
            return true;
        }

        String requestURI = request.getRequestURI();
        return requestURI != null && (requestURI.startsWith("/api/") || requestURI.contains("/api/"));
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
