package io.contexa.contexaidentity.security.handler;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 단일 인증용 세션 기반 실패 핸들러
 *
 * FORM, REST, OTT, PASSKEY 공용으로 사용
 * OAuth2/JWT 토큰이 아닌 세션 기반 인증 처리
 * MFA 기능 일체 제외
 *
 * Spring Security의 SimpleUrlAuthenticationFailureHandler 참고
 */
@Slf4j
@Component
public class SessionSingleAuthFailureHandler extends SessionBasedFailureHandler {

    private final AuthContextProperties authContextProperties;

    public SessionSingleAuthFailureHandler(AuthResponseWriter responseWriter,
                                          AuthContextProperties authContextProperties) {
        super(responseWriter);
        this.authContextProperties = authContextProperties;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        onAuthenticationFailure(request, response, exception, null, null, null);
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception, @Nullable FactorContext factorContext,
                                        @Nullable FailureType failureType, @Nullable Map<String, Object> errorDetails)
            throws IOException, ServletException {

        if (response.isCommitted()) {
            log.warn("Response already committed for authentication failure");
            return;
        }

        log.debug("Processing session single auth failure: {}", exception.getMessage());

        // 에러 코드 및 메시지 결정
        String errorCode = "PRIMARY_AUTH_FAILED";
        String errorMessage = "아이디 또는 비밀번호가 잘못되었습니다.";

        // FailureType에 따른 에러 메시지 커스터마이징
        if (failureType != null && failureType == FailureType.PRIMARY_AUTH_FAILED) {
            errorCode = "PRIMARY_AUTH_FAILED";
            errorMessage = "아이디 또는 비밀번호가 잘못되었습니다.";
        } else if (exception.getMessage() != null && !exception.getMessage().isBlank()) {
            errorMessage = exception.getMessage();
        }

        // 실패 리다이렉트 URL - AuthContextProperties에서 가져오기
        String loginFailureUrl = authContextProperties.getUrls().getSingle().getLoginFailure();
        String failureUrl = request.getContextPath() + loginFailureUrl;

        // 에러 코드를 쿼리 파라미터로 추가
        if (!loginFailureUrl.contains("?")) {
            failureUrl += "?error=" + errorCode.toLowerCase();
        } else {
            failureUrl += "&error=" + errorCode.toLowerCase();
        }

        // API 요청과 일반 요청 구분 처리
        if (isApiRequest(request)) {
            // JSON 응답
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("authenticated", false);
            responseData.put("message", errorMessage);
            responseData.put("errorCode", errorCode);
            responseData.put("nextStepUrl", failureUrl);

            if (errorDetails != null && !errorDetails.isEmpty()) {
                responseData.put("errorDetails", errorDetails);
            }

            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED,
                    errorCode, errorMessage, request.getRequestURI(), responseData);

            log.debug("Session single auth failure (JSON): errorCode={}", errorCode);
        } else {
            // 리다이렉트
            response.sendRedirect(failureUrl);
            log.debug("Session single auth failure (redirect) to: {}", failureUrl);
        }
    }
}
