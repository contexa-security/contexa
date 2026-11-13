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
import org.springframework.security.authentication.CredentialsExpiredException;
import io.contexa.contexacommon.security.LocalCredentialsVerifier;
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

    /** Where a failed page sign-in goes when its step names no failure address: the sign-in page with the error. */
    private static final String DEFAULT_FAILURE_URL = "/login?error";

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
        if (exception instanceof CredentialsExpiredException) {
            ExpiredPasswordAnswer.write(request, response, responseWriter,
                    ExpiredPasswordAnswer.accountOf(exception, request.getParameter("username")), isApiRequest(request));
            return;
        }


        // The same words whatever refused the sign-in, as in the MFA flow: the reason would tell who has an account.
        String errorCode = failureType == FailureType.PRIMARY_AUTH_FAILED
                ? "PRIMARY_AUTH_FAILED" : "AUTHENTICATION_FAILED";
        String errorMessage = LocalCredentialsVerifier.SIGN_IN_REFUSED;

        Map<String, Object> responseData = new HashMap<>();
        responseData.put("authenticated", false);
        responseData.put("message", errorMessage);
        responseData.put("errorCode", errorCode);

        if (errorDetails != null && !errorDetails.isEmpty()) {
            responseData.put("errorDetails", errorDetails);
        }
        // The application's failure handler (the flow's failureHandler option) runs first and may write the response
        // itself, as in the MFA flows; Contexa writes its own only when it did not.
        executeDelegateHandler(request, response, exception, factorContext,
                failureType != null ? failureType : FailureType.PRIMARY_AUTH_FAILED, responseData);
        if (response.isCommitted()) {
            return;
        }
        if (!isApiRequest(request)) {
            // A page form is sent back to the step's failure address, as in the session state; the JSON answer was
            // shown to the person as it was.
            String failureUrl = failureUrl(request);
            response.sendRedirect(request.getContextPath() + (failureUrl != null ? failureUrl : DEFAULT_FAILURE_URL));
            return;
        }
        writeErrorResponse(request, response, errorCode, errorMessage, responseData);
    }

    private static boolean isApiRequest(HttpServletRequest request) {
        String acceptHeader = request.getHeader("Accept");
        if (acceptHeader != null && acceptHeader.contains("application/json")) {
            return true;
        }
        String contentType = request.getContentType();
        if (contentType != null && contentType.contains("application/json")) {
            return true;
        }
        String requestURI = request.getRequestURI();
        return requestURI != null && requestURI.contains("/api/");
    }
}
