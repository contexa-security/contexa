package io.contexa.contexaidentity.security.handler;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.AuthenticationException;

import java.io.IOException;
import java.util.Map;

/**
 * OAuth2/JWT 토큰 기반 실패 핸들러의 추상 부모 클래스
 *
 * 에러 응답 작성 등의 공통 로직 제공
 * 하위 클래스에서 에러 메시지 구성 로직만 구현
 */
@Slf4j
public abstract class AbstractTokenBasedFailureHandler implements PlatformAuthenticationFailureHandler {

    protected final AuthResponseWriter responseWriter;

    private PlatformAuthenticationFailureHandler delegateHandler;

    protected AbstractTokenBasedFailureHandler(AuthResponseWriter responseWriter) {
        this.responseWriter = responseWriter;
    }

    /**
     * 사용자 커스텀 핸들러 설정
     *
     * @param delegateHandler 위임할 실패 핸들러
     */
    public void setDelegateHandler(@Nullable PlatformAuthenticationFailureHandler delegateHandler) {
        this.delegateHandler = delegateHandler;
        if (delegateHandler != null) {
            log.info("Delegate failure handler set: {}", delegateHandler.getClass().getName());
        }
    }

    /**
     * 에러 응답 작성 공통 로직
     *
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @param errorCode 에러 코드
     * @param errorMessage 에러 메시지
     * @param errorDetails 에러 상세 정보
     * @throws IOException IO 예외
     */
    protected void writeErrorResponse(HttpServletRequest request, HttpServletResponse response,
                                      String errorCode, String errorMessage,
                                      Map<String, Object> errorDetails) throws IOException {
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED,
                errorCode, errorMessage, request.getRequestURI(), errorDetails);
    }

    /**
     * 위임 핸들러 실행 공통 로직
     *
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @param exception 인증 예외
     * @param factorContext MFA 컨텍스트 (nullable)
     * @param failureType 실패 유형
     * @param errorDetails 에러 상세 정보
     * @return 위임 핸들러 실행 여부
     */
    protected final boolean executeDelegateHandler(HttpServletRequest request,
                                                    HttpServletResponse response,
                                                    AuthenticationException exception,
                                                    @Nullable FactorContext factorContext,
                                                    PlatformAuthenticationFailureHandler.FailureType failureType,
                                                    Map<String, Object> errorDetails) {
        if (delegateHandler != null && !response.isCommitted()) {
            try {
                delegateHandler.onAuthenticationFailure(request, response, exception,
                        factorContext, failureType, errorDetails);
                return true;
            } catch (Exception e) {
                log.error("Error in delegate failure handler", e);
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
