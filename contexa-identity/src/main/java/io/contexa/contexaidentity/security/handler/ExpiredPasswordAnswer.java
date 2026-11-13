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

import io.contexa.contexacommon.security.ContexaConsolePaths;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * The answer to a sign-in with the right password whose password has expired, the same for every flow: a page is sent
 * to the password change page, a script gets {@code 401 CREDENTIALS_EXPIRED} with that page as {@code nextStepUrl}.
 * The account name goes to the page in the session, not in the address, where browsers and proxies keep it.
 */
final class ExpiredPasswordAnswer {

    static final String ERROR_CODE = "CREDENTIALS_EXPIRED";
    static final String MESSAGE = "Password has expired";

    private ExpiredPasswordAnswer() {
    }

    /** The account the refused sign-in named: from the attempt itself, which also covers a JSON body. */
    @Nullable
    static String accountOf(AuthenticationException exception, @Nullable String fallback) {
        Authentication attempt = exception.getAuthenticationRequest();
        if (attempt != null && StringUtils.hasText(attempt.getName())) {
            return attempt.getName();
        }
        return fallback;
    }

    /** The address of the password change page for this request, with the account name kept for it. */
    static String passwordChangeAddress(HttpServletRequest request, @Nullable String username) {
        if (StringUtils.hasText(username)) {
            request.getSession(true).setAttribute(ContexaConsolePaths.PASSWORD_CHANGE_USERNAME_ATTRIBUTE, username);
        }
        return request.getContextPath() + ContexaConsolePaths.PASSWORD_CHANGE + "?expired=true";
    }

    static void write(HttpServletRequest request, HttpServletResponse response, AuthResponseWriter responseWriter,
                      @Nullable String username, boolean script) throws IOException {
        String passwordChange = passwordChangeAddress(request, username);
        if (!script) {
            response.sendRedirect(passwordChange);
            return;
        }
        Map<String, Object> details = new HashMap<>();
        details.put("authenticated", false);
        details.put("errorCode", ERROR_CODE);
        details.put("nextStepUrl", passwordChange);
        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, ERROR_CODE, MESSAGE,
                request.getRequestURI(), details);
    }
}
