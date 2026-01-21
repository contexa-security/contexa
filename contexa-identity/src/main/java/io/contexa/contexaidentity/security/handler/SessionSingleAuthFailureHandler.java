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

        String errorCode = "PRIMARY_AUTH_FAILED";
        String errorMessage = "아이디 또는 비밀번호가 잘못되었습니다.";

        if (failureType != null && failureType == FailureType.PRIMARY_AUTH_FAILED) {
            errorCode = "PRIMARY_AUTH_FAILED";
            errorMessage = "아이디 또는 비밀번호가 잘못되었습니다.";
        } else if (exception.getMessage() != null && !exception.getMessage().isBlank()) {
            errorMessage = exception.getMessage();
        }

        String loginFailureUrl = authContextProperties.getUrls().getSingle().getLoginFailure();
        String failureUrl = request.getContextPath() + loginFailureUrl;

        if (!loginFailureUrl.contains("?")) {
            failureUrl += "?error=" + errorCode.toLowerCase();
        } else {
            failureUrl += "&error=" + errorCode.toLowerCase();
        }

        if (isApiRequest(request)) {
            
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

                    } else {
            
            response.sendRedirect(failureUrl);
                    }
    }
}
