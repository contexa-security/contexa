package io.contexa.contexaidentity.security.handler;

import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

/**
 * 세션 기반 성공 핸들러의 추상 부모 클래스
 *
 * SavedRequest 처리, 리다이렉트 URL 결정 등의 공통 로직 제공
 * Spring Security의 SavedRequestAwareAuthenticationSuccessHandler 참고
 */
@Slf4j
public abstract class SessionBasedSuccessHandler implements PlatformAuthenticationSuccessHandler {

    protected final AuthResponseWriter responseWriter;
    protected final AuthContextProperties authContextProperties;
    protected final RequestCache requestCache = new HttpSessionRequestCache();

    protected SessionBasedSuccessHandler(AuthResponseWriter responseWriter,
                                         AuthContextProperties authContextProperties) {
        this.responseWriter = responseWriter;
        this.authContextProperties = authContextProperties;
    }

    /**
     * SavedRequest 기반 리다이렉트 URL 결정 공통 로직
     *
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @return 리다이렉트 URL
     */
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        SavedRequest savedRequest = requestCache.getRequest(request, response);

        if (savedRequest != null) {
            String redirectUrl = savedRequest.getRedirectUrl();

            // URL 검증: 유효한 애플리케이션 URL인지 확인
            if (isValidRedirectUrl(redirectUrl)) {
                requestCache.removeRequest(request, response);
                return redirectUrl;
            } else {
                log.warn("Invalid saved redirect URL ignored: {}", redirectUrl);
            }
        }

        // SavedRequest가 없거나 유효하지 않으면 기본 URL 사용
        return getDefaultTargetUrl(request);
    }

    /**
     * 기본 리다이렉트 URL 결정 - 하위 클래스에서 구현
     *
     * @param request HTTP 요청
     * @return 기본 리다이렉트 URL
     */
    protected abstract String getDefaultTargetUrl(HttpServletRequest request);

    /**
     * Redirect URL 유효성 검증
     * Chrome DevTools, .well-known, favicon 등 내부 요청 필터링
     *
     * @param url 검증할 URL
     * @return 유효한 URL이면 true, 그렇지 않으면 false
     */
    protected boolean isValidRedirectUrl(String url) {
        if (url == null || url.isBlank()) {
            return false;
        }

        // 제외할 패턴들
        String[] invalidPatterns = {
            "/.well-known/",
            "/favicon.ico",
            "chrome-extension://",
            "about:",
            "data:",
            "blob:",
            "javascript:"
        };

        for (String pattern : invalidPatterns) {
            if (url.contains(pattern)) {
                return false;
            }
        }

        return true;
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
