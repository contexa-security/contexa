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
package io.contexa.contexaiam.security.core;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Releases per-request {@link LoginPolicyService} idempotency state at the end of each HTTP
 * request so it cannot leak into the next request that reuses the same Tomcat worker thread.
 *
 * <p>Without this cleanup, the {@code ThreadLocal} set inside {@code LoginPolicyService}
 * accumulates entries across requests on a recycled thread. Two failure events in two
 * separate requests on the same thread that happen to share the same
 * {@code username + ip} would be deduplicated incorrectly, so a real second failure would
 * never reach the database counter. The 32-key cap inside the service caps memory but does
 * not eliminate the cross-request deduplication window.</p>
 *
 * <p>The filter surrounds the security chain, and its cleanup fires when the chain has returned.
 * A filter behind the chain would never run for a failed sign-in, which ends inside the chain.
 * It runs for every path: removing the marker costs nothing, and a path left out because it only
 * looks like a static file would leave the marker of a real failure behind.</p>
 */
public class LoginAttemptCleanupFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response);
        } finally {
            LoginPolicyService.clearRequestState();
        }
    }
}
