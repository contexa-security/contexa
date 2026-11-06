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
package io.contexa.contexaidentity.security.filter;

import io.contexa.contexaidentity.security.service.ott.OneTimeTokenAddressRefusedException;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import io.contexa.contexaidentity.security.utils.WebUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

/**
 * Answers a code request that named another address than the one registered for the account. Spring Security's token
 * filter has nothing to catch that refusal with, so it reached the container, or the MFA flow as a system error, as a
 * 500. Nothing is sent and nothing is counted: a browser goes back to the page that asks for the code, an API client
 * gets 400, and the flow stays where it was.
 */
public class OneTimeTokenAddressRefusalFilter extends OncePerRequestFilter {

    public static final String ERROR_CODE = "OTT_ADDRESS_MISMATCH";
    public static final String ERROR_PARAMETER = "address_mismatch";
    private static final String MESSAGE = "The address does not match the one registered for this account";

    private final AuthResponseWriter responseWriter;
    private String requestPage;

    public OneTimeTokenAddressRefusalFilter(AuthResponseWriter responseWriter, String requestPage) {
        this.responseWriter = responseWriter;
        this.requestPage = requestPage;
    }

    /** The page of the flow: a flow with a URL prefix knows it only when its chain is customized. */
    public void setRequestPage(String requestPage) {
        this.requestPage = requestPage;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response);
        } catch (OneTimeTokenAddressRefusedException refused) {
            if (WebUtil.isApiOrAjaxRequest(request)) {
                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, ERROR_CODE, MESSAGE,
                        request.getRequestURI(), Map.of("error", ERROR_CODE, "message", MESSAGE));
            } else {
                response.sendRedirect(request.getContextPath() + requestPage + "?error=" + ERROR_PARAMETER);
            }
        }
    }
}
