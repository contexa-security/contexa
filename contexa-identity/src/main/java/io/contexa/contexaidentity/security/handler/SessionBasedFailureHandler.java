package io.contexa.contexaidentity.security.handler;

import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public abstract class SessionBasedFailureHandler implements PlatformAuthenticationFailureHandler {

    protected final AuthResponseWriter responseWriter;

    protected SessionBasedFailureHandler(AuthResponseWriter responseWriter) {
        this.responseWriter = responseWriter;
    }

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
}
