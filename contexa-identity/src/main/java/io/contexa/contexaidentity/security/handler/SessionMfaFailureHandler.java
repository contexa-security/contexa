package io.contexa.contexaidentity.security.handler;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.AuthenticationException;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
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

        String errorCode = determineErrorCode(failureType, factorContext);
        String errorMessage = determineErrorMessage(failureType, exception);

        String mfaFailureUrl = authContextProperties.getUrls().getMfa().getFailure();
        String failureUrl = request.getContextPath() + mfaFailureUrl;

        if (!mfaFailureUrl.contains("?")) {
            failureUrl += "?error=" + errorCode.toLowerCase();
        } else {
            failureUrl += "&error=" + errorCode.toLowerCase();
        }

        if (isApiRequest(request)) {
            
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("authenticated", false);
            responseData.put("mfaCompleted", false);
            responseData.put("message", errorMessage);
            responseData.put("errorCode", errorCode);
            responseData.put("nextStepUrl", failureUrl);

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

                    } else {
            
            response.sendRedirect(failureUrl);
                    }
    }

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
