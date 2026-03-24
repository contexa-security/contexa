package io.contexa.contexaidentity.security.handler;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
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
    private final LoginPolicyHandler loginPolicyHandler;

    public SessionSingleAuthFailureHandler(AuthResponseWriter responseWriter,
                                           AuthContextProperties authContextProperties,
                                           @Nullable LoginPolicyHandler loginPolicyHandler) {
        super(responseWriter);
        this.authContextProperties = authContextProperties;
        this.loginPolicyHandler = loginPolicyHandler;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException{
        onAuthenticationFailure(request, response, exception, null, null, null);
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception, @Nullable FactorContext factorContext,
                                        @Nullable FailureType failureType, @Nullable Map<String, Object> errorDetails)
            throws IOException {

        if (response.isCommitted()) {
            log.error("Response already committed for authentication failure");
            return;
        }

        // Record login failure
        if (loginPolicyHandler != null) {
            try {
                String username = request.getParameter("username");
                if (username != null && !username.isBlank()) {
                    loginPolicyHandler.onLoginFailure(username);
                }
            } catch (Exception e) {
                log.error("Failed to record login failure", e);
            }
        }

        String errorCode = "PRIMARY_AUTH_FAILED";
        String errorMessage = "Invalid username or password.";

        if (failureType == FailureType.PRIMARY_AUTH_FAILED) {
            errorCode = "PRIMARY_AUTH_FAILED";
            errorMessage = "Invalid username or password.";
        } else if (exception.getMessage() != null && !exception.getMessage().isBlank()) {
            errorMessage = exception.getMessage();
        }

        String loginFailureUrl = getDefaultTargetUrl(request);
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

    @Override
    protected String getDefaultTargetUrl(HttpServletRequest request) {
        if (defaultTargetUrl != null) return defaultTargetUrl;
        return authContextProperties.getUrls().getPrimary().getLoginFailure();
    }
}
