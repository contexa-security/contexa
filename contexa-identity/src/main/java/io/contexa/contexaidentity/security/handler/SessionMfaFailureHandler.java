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
 * MFA 인증용 세션 기반 실패 핸들러
 *
 * FORM, REST, OTT, PASSKEY MFA 공용으로 사용
 * OAuth2/JWT 토큰이 아닌 세션 기반 인증 처리
 * MFA 과정에서 발생한 실패 처리
 *
 * Spring Security의 SimpleUrlAuthenticationFailureHandler 참고
 */
@Slf4j
@Component
public class SessionMfaFailureHandler extends SessionBasedFailureHandler {

    private final AuthContextProperties authContextProperties;

    public SessionMfaFailureHandler(AuthResponseWriter responseWriter,
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
            log.warn("Response already committed for MFA authentication failure");
            return;
        }

        log.debug("Processing session MFA authentication failure: {}", exception.getMessage());

        // 에러 코드 및 메시지 결정
        String errorCode = determineErrorCode(failureType, factorContext);
        String errorMessage = determineErrorMessage(failureType, exception);

        // 실패 리다이렉트 URL - AuthContextProperties에서 가져오기
        String mfaFailureUrl = authContextProperties.getUrls().getMfa().getFailure();
        String failureUrl = request.getContextPath() + mfaFailureUrl;

        // 에러 코드를 쿼리 파라미터로 추가
        if (!mfaFailureUrl.contains("?")) {
            failureUrl += "?error=" + errorCode.toLowerCase();
        } else {
            failureUrl += "&error=" + errorCode.toLowerCase();
        }

        // API 요청과 일반 요청 구분 처리
        if (isApiRequest(request)) {
            // JSON 응답
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("authenticated", false);
            responseData.put("mfaCompleted", false);
            responseData.put("message", errorMessage);
            responseData.put("errorCode", errorCode);
            responseData.put("nextStepUrl", failureUrl);

            // FactorContext 정보 추가
            if (factorContext != null) {
                responseData.put("mfaSessionId", factorContext.getMfaSessionId());
                responseData.put("currentState", factorContext.getCurrentState());
                responseData.put("retryCount", factorContext.getRetryCount());
            }

            if (errorDetails != null && !errorDetails.isEmpty()) {
                responseData.put("errorDetails", errorDetails);
            }

            responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED,
                    errorCode, errorMessage, request.getRequestURI(), responseData);

            log.debug("Session MFA failure (JSON): errorCode={}", errorCode);
        } else {
            // 리다이렉트
            response.sendRedirect(failureUrl);
            log.debug("Session MFA failure (redirect) to: {}", failureUrl);
        }
    }

    /**
     * 실패 유형에 따른 에러 코드 결정
     */
    private String determineErrorCode(FailureType failureType, FactorContext factorContext) {
        if (failureType == null) {
            return "MFA_FAILED";
        }

        switch (failureType) {
            case PRIMARY_AUTH_FAILED:
                return "PRIMARY_AUTH_FAILED";
            case MFA_FACTOR_FAILED:
                return "MFA_FACTOR_FAILED";
            case MFA_MAX_ATTEMPTS_EXCEEDED:
                return "MFA_MAX_ATTEMPTS_EXCEEDED";
            case MFA_SESSION_NOT_FOUND:
                return "MFA_SESSION_NOT_FOUND";
            case MFA_GLOBAL_FAILURE:
                return "MFA_GLOBAL_FAILURE";
            default:
                return "MFA_FAILED";
        }
    }

    /**
     * 실패 유형에 따른 에러 메시지 결정
     */
    private String determineErrorMessage(FailureType failureType, AuthenticationException exception) {
        if (failureType == null) {
            return exception.getMessage() != null ? exception.getMessage() : "MFA 인증에 실패했습니다.";
        }

        switch (failureType) {
            case PRIMARY_AUTH_FAILED:
                return "1차 인증에 실패했습니다.";
            case MFA_FACTOR_FAILED:
                return "2차 인증(Factor) 검증에 실패했습니다.";
            case MFA_MAX_ATTEMPTS_EXCEEDED:
                return "최대 시도 횟수를 초과했습니다.";
            case MFA_SESSION_NOT_FOUND:
                return "MFA 세션을 찾을 수 없습니다. 다시 로그인해주세요.";
            case MFA_GLOBAL_FAILURE:
                return "MFA 인증 과정에서 오류가 발생했습니다.";
            default:
                return exception.getMessage() != null ? exception.getMessage() : "MFA 인증에 실패했습니다.";
        }
    }
}
