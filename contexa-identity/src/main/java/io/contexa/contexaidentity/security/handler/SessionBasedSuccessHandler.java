/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
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
    protected volatile String defaultTargetUrl;
    protected volatile boolean alwaysUse;

    protected SessionBasedSuccessHandler(AuthResponseWriter responseWriter,
                                         AuthContextProperties authContextProperties) {
        this.responseWriter = responseWriter;
        this.authContextProperties = authContextProperties;
    }

    @Override
    public void setDefaultTargetUrl(String defaultTargetUrl) {
        this.defaultTargetUrl = defaultTargetUrl;
    }

    @Override
    public void setAlwaysUse(boolean alwaysUse) {
        this.alwaysUse = alwaysUse;
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        RequestCache localRequestCache = new HttpSessionRequestCache();
        SavedRequest savedRequest = localRequestCache.getRequest(request, response);

        if (savedRequest != null) {
            String redirectUrl = savedRequest.getRedirectUrl();

            if (isValidRedirectUrl(redirectUrl)) {
                localRequestCache.removeRequest(request, response);
                return redirectUrl;
            } else {
                log.error("Invalid saved redirect URL ignored: {}", redirectUrl);
            }
        }

        return getDefaultTargetUrl(request);
    }

    protected abstract String getDefaultTargetUrl(HttpServletRequest request);

    protected boolean isValidRedirectUrl(String url) {
        if (url == null || url.isBlank()) {
            return false;
        }

        if (url.startsWith("http://") || url.startsWith("https://") || url.startsWith("//")) {
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
