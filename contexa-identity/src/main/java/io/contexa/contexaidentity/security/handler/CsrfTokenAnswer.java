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

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;

import java.util.Map;

/**
 * The CSRF token of the session a completed sign-in leaves, in the body of its answer. Signing in replaces the token;
 * a page that signed in with a script and stays open (an SPA, a page of the application using the SDK) had no way to
 * learn the new one, so its next POST (sign-out, token refresh) was refused.
 */
final class CsrfTokenAnswer {

    private CsrfTokenAnswer() {
    }

    static void put(Map<String, Object> body, HttpServletRequest request) {
        if (request.getAttribute(CsrfToken.class.getName()) instanceof CsrfToken token) {
            body.put("csrfToken", token.getToken());
            body.put("csrfHeader", token.getHeaderName());
            body.put("csrfParameter", token.getParameterName());
        }
    }
}
