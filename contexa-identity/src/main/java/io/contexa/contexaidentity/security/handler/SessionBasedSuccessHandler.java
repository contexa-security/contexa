package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

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

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        SavedRequest savedRequest = requestCache.getRequest(request, response);

        if (savedRequest != null) {
            String redirectUrl = savedRequest.getRedirectUrl();

            if (isValidRedirectUrl(redirectUrl)) {
                requestCache.removeRequest(request, response);
                return redirectUrl;
            } else {
                log.warn("Invalid saved redirect URL ignored: {}", redirectUrl);
            }
        }

        return getDefaultTargetUrl(request);
    }

    protected abstract String getDefaultTargetUrl(HttpServletRequest request);

    protected boolean isValidRedirectUrl(String url) {
        if (url == null || url.isBlank()) {
            return false;
        }

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
