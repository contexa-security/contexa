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
package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexacore.security.SessionAccountRefresher;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.lang.Nullable;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Stands in the console's chain, behind the loading of its security context. It marks the request as the console's
 * (Q-17), and keeps an open console session in step with its account (Q-14). An account that is gone or disabled signs
 * the console out and leaves the HTTP session alone: the application's user may be signed in on the same one.
 */
final class ConsoleSessionFilter extends OncePerRequestFilter {

    private final String contextKey;
    @Nullable
    private final SessionAccountRefresher accountRefresher;

    ConsoleSessionFilter(String contextKey, @Nullable SessionAccountRefresher accountRefresher) {
        this.contextKey = contextKey;
        this.accountRefresher = accountRefresher;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        ConsoleSession.mark(request);
        SecurityContext context = SecurityContextHolder.getContext();
        if (accountRefresher != null
                && accountRefresher.refresh(context, request, contextKey) == SessionAccountRefresher.Outcome.ACCOUNT_ENDED) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.removeAttribute(contextKey);
            }
            SecurityContextHolder.clearContext();
        }
        chain.doFilter(request, response);
    }
}
