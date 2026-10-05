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
package io.contexa.contexaidentity.security.handler.logout;

import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;
import java.util.Map;
import io.contexa.contexaidentity.security.utils.WebUtil;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

/**
 * LogoutSuccessHandler for OAuth2/REST flows.
 * Writes JSON response {"status":"LOGGED_OUT"} after successful logout. When a logout success URL is set,
 * a plain browser submission is redirected there instead, as the session state does.
 */
public class OAuth2LogoutSuccessHandler implements LogoutSuccessHandler {

    private final AuthResponseWriter responseWriter;
    @Nullable
    private final String logoutSuccessUrl;

    public OAuth2LogoutSuccessHandler(AuthResponseWriter responseWriter) {
        this(responseWriter, null);
    }

    public OAuth2LogoutSuccessHandler(AuthResponseWriter responseWriter, @Nullable String logoutSuccessUrl) {
        this.responseWriter = responseWriter;
        this.logoutSuccessUrl = logoutSuccessUrl;
    }

    /**
     * Returns a handler that redirects plain browser submissions to the given URL of a flow.
     */
    public OAuth2LogoutSuccessHandler withLogoutSuccessUrl(@Nullable String url) {
        return new OAuth2LogoutSuccessHandler(responseWriter, url);
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {

        if (response.isCommitted()) {
            return;
        }

        if (StringUtils.hasText(logoutSuccessUrl) && !WebUtil.isApiOrAjaxRequest(request)) {
            response.sendRedirect(request.getContextPath() + logoutSuccessUrl);
            return;
        }

        responseWriter.writeSuccessResponse(response, Map.of("status", "LOGGED_OUT"), HttpServletResponse.SC_OK);
    }
}
