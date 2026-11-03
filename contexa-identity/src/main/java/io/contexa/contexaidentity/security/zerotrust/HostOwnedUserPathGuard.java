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
package io.contexa.contexaidentity.security.zerotrust;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Contexa's pages for the signed-in user of an application that owns sign-in (HOST_OWNED, ownership design S-3): the
 * decision screens, the step-up, and an agent's delegations and confirmations. They answer the user the application
 * signed in, so an anonymous request gets 401 here instead of reaching them, whatever the application's own rules let
 * through. It runs after the application's chain and never changes its authentication.
 */
public class HostOwnedUserPathGuard extends OncePerRequestFilter {

    /**
     * The user's paths under the console's /contexa/admin: the block screen asks for the release of a block, the
     * analysis-pending screen follows its analysis. The console chain leaves them to this guard.
     */
    public static final List<String> ADMIN_SELF_SERVICE_PREFIXES = List.of(
            "/contexa/admin/api/aiam/zero-trust",
            "/contexa/admin/api/aiam/sse/zero-trust");

    /** The URL patterns of the user's pages, as a servlet registration takes them. */
    public static final List<String> URL_PATTERNS = List.of(
            "/contexa/zero-trust/*",
            HostOwnedStepUp.STEP_UP_PATH,
            HostOwnedStepUp.STEP_UP_PATH + "/*",
            "/contexa/api/agent-delegations",
            "/contexa/api/agent-delegations/*",
            "/contexa/api/agent-confirmations",
            "/contexa/api/agent-confirmations/*",
            "/contexa/agent-confirmations",
            "/contexa/agent-confirmations/*",
            ADMIN_SELF_SERVICE_PREFIXES.get(0) + "/*",
            ADMIN_SELF_SERVICE_PREFIXES.get(1) + "/*");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.getWriter().write("{\"error\":\"AUTHENTICATION_REQUIRED\"}");
            return;
        }
        chain.doFilter(request, response);
    }
}
