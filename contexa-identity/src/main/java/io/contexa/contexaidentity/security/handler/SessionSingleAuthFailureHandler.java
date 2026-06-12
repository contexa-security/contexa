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
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.ServletException;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.AuthenticationException;

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

        if (exception instanceof CredentialsExpiredException) {
            String expiredUsername = request.getParameter("username");
            String passwordChangeUrl = request.getContextPath() + "/password-change?username="
                    + URLEncoder.encode(expiredUsername != null ? expiredUsername : "", StandardCharsets.UTF_8) + "&expired=true";
            if (isApiRequest(request)) {
                Map<String, Object> responseData = new HashMap<>();
                responseData.put("authenticated", false);
                responseData.put("errorCode", "CREDENTIALS_EXPIRED");
                responseData.put("message", "Password has expired");
                responseData.put("nextStepUrl", passwordChangeUrl);
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED,
                        "CREDENTIALS_EXPIRED", "Password has expired", request.getRequestURI(), responseData);
            } else {
                response.sendRedirect(passwordChangeUrl);
            }
            return;
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
