package io.contexa.contexaidentity.security.handler;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
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
public class OAuth2SingleAuthFailureHandler extends AbstractTokenBasedFailureHandler {

    public OAuth2SingleAuthFailureHandler(AuthResponseWriter responseWriter) {
        super(responseWriter);
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

        String errorCode = "AUTHENTICATION_FAILED";
        String errorMessage = "인증에 실패했습니다. 사용자명 또는 비밀번호를 확인하세요.";

        if (failureType == FailureType.PRIMARY_AUTH_FAILED) {
            errorCode = "PRIMARY_AUTH_FAILED";
            errorMessage = "아이디 또는 비밀번호가 잘못되었습니다.";
        } else if (exception.getMessage() != null && !exception.getMessage().isBlank()) {
            
            errorMessage = exception.getMessage();
        }

        Map<String, Object> responseData = new HashMap<>();
        responseData.put("authenticated", false);
        responseData.put("message", errorMessage);
        responseData.put("errorCode", errorCode);

        if (errorDetails != null && !errorDetails.isEmpty()) {
            responseData.put("errorDetails", errorDetails);
        }

        writeErrorResponse(request, response, errorCode, errorMessage, responseData);

            }
}
