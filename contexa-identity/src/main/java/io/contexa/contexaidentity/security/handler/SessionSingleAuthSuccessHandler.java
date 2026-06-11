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
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class SessionSingleAuthSuccessHandler extends SessionBasedSuccessHandler {

    private final LoginPolicyHandler loginPolicyHandler;

    public SessionSingleAuthSuccessHandler(AuthResponseWriter responseWriter,
                                           AuthContextProperties authContextProperties,
                                           @Nullable LoginPolicyHandler loginPolicyHandler) {
        super(responseWriter, authContextProperties);
        this.loginPolicyHandler = loginPolicyHandler;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        onAuthenticationSuccess(request, response, authentication, null);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication,
                                        @Nullable TokenTransportResult providedResult) throws IOException {

        if (response.isCommitted()) {
            log.error("Response already committed for user: {}", authentication.getName());
            return;
        }

        if (loginPolicyHandler != null) {
            try {
                loginPolicyHandler.onLoginSuccess(authentication.getName(), request.getRemoteAddr());
            } catch (Exception e) {
                log.error("Failed to record login success for user: {}", authentication.getName(), e);
            }
        }

        String targetUrl = determineTargetUrl(request, response);

        if (isApiRequest(request)) {

            Map<String, Object> responseData = new HashMap<>();
            responseData.put("authenticated", true);
            responseData.put("redirectUrl", targetUrl);
            responseData.put("message", "Login successful!");
            responseData.put("username", authentication.getName());
            responseData.put("stateType", "SESSION");

            responseWriter.writeSuccessResponse(response, responseData, HttpServletResponse.SC_OK);
        } else {
            response.sendRedirect(targetUrl);
        }
    }

    @Override
    protected String getDefaultTargetUrl(HttpServletRequest request) {

        if (alwaysUse && defaultTargetUrl != null) {
            return request.getContextPath() + defaultTargetUrl;
        }

        if (defaultTargetUrl != null) return request.getContextPath() + defaultTargetUrl;

        String successUrl = authContextProperties.getUrls().getSingle().getLoginSuccess();
        return request.getContextPath() + successUrl;
    }
}
