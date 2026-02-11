package io.contexa.contexaidentity.security.handler;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.AuthenticationException;

import java.io.IOException;
import java.util.Map;

@Slf4j
public abstract class AbstractTokenBasedFailureHandler implements PlatformAuthenticationFailureHandler {

    protected final AuthResponseWriter responseWriter;
    private PlatformAuthenticationFailureHandler delegateHandler;

    protected AbstractTokenBasedFailureHandler(AuthResponseWriter responseWriter) {
        this.responseWriter = responseWriter;
    }

    public void setDelegateHandler(@Nullable PlatformAuthenticationFailureHandler delegateHandler) {
        this.delegateHandler = delegateHandler;
        if (delegateHandler != null) {
        }
    }

    protected void writeErrorResponse(HttpServletRequest request, HttpServletResponse response,
                                      String errorCode, String errorMessage,
                                      Map<String, Object> errorDetails) throws IOException {
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED,
                errorCode, errorMessage, request.getRequestURI(), errorDetails);
    }

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
