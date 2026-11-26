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

import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.List;

/**
 * Contexa's pages for the signed-in user of an application that signs its users in itself (mode SANDBOX, with either
 * ownership; ownership design S-3): the
 * decision screens, the step-up, and an agent's delegations and confirmations. They answer the user the application
 * signed in, so an anonymous request gets 401 here instead of reaching them, whatever the application's own rules let
 * through. It runs after the application's chain and never changes its authentication.
 */
public class SandboxUserPathGuard extends OncePerRequestFilter {

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
            SandboxStepUp.STEP_UP_PATH,
            SandboxStepUp.STEP_UP_PATH + "/*",
            "/contexa/api/agent-delegations",
            "/contexa/api/agent-delegations/*",
            "/contexa/api/agent-confirmations",
            "/contexa/api/agent-confirmations/*",
            "/contexa/agent-confirmations",
            "/contexa/agent-confirmations/*",
            ADMIN_SELF_SERVICE_PREFIXES.get(0) + "/*",
            ADMIN_SELF_SERVICE_PREFIXES.get(1) + "/*");

    /**
     * The user is the one Contexa decides for (R-10): the application's signed-in user, else the user the bridge resolved
     * for Contexa alone. Such a user is not in the application's security context, so Contexa's own pages behind this
     * guard are given the request with that user as its principal; the security context stays as the application left it.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Authentication authentication = ContexaIdentity.of(request);
        if (!ContexaIdentity.signedIn(authentication)) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.getWriter().write("{\"error\":\"AUTHENTICATION_REQUIRED\"}");
            return;
        }
        if (authentication != SecurityContextHolder.getContext().getAuthentication() && request.getUserPrincipal() == null) {
            chain.doFilter(new ContexaUserRequest(request, authentication), response);
            return;
        }
        chain.doFilter(request, response);
    }

    /** A request of Contexa's own pages whose user only Contexa resolved: that user is its principal there. */
    private static final class ContexaUserRequest extends HttpServletRequestWrapper {

        private final Authentication user;

        private ContexaUserRequest(HttpServletRequest request, Authentication user) {
            super(request);
            this.user = user;
        }

        @Override
        public Principal getUserPrincipal() {
            return user;
        }

        @Override
        public String getRemoteUser() {
            return user.getName();
        }
    }
}
