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

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
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
public class OAuth2SingleAuthFailureHandler extends AbstractTokenBasedFailureHandler {

    private final LoginPolicyHandler loginPolicyHandler;

    public OAuth2SingleAuthFailureHandler(AuthResponseWriter responseWriter,
                                          @Nullable LoginPolicyHandler loginPolicyHandler) {
        super(responseWriter);
        this.loginPolicyHandler = loginPolicyHandler;
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
            throws IOException{

        if (response.isCommitted()) {
            log.error("Response already committed for authentication failure");
            return;
        }


        String errorCode = "AUTHENTICATION_FAILED";
        String errorMessage = "Authentication failed. Please check your username or password.";

        if (failureType == FailureType.PRIMARY_AUTH_FAILED) {
            errorCode = "PRIMARY_AUTH_FAILED";
            errorMessage = "Invalid username or password.";
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
