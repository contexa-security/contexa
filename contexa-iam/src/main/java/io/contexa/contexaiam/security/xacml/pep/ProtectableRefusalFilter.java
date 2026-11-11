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
package io.contexa.contexaiam.security.xacml.pep;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.Nullable;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Answers the refusal of a {@code @Protectable} call that no Spring Security chain answered. On a path a chain of the
 * application covers, the chain's exception translation answers the refusal before it gets here, as it always did. On a
 * path no chain covers nothing translated it, and the servlet container answered 500. Here it is answered as that
 * translation answers with its defaults: 401 for a call without a user, 403 for one the method policies refused, through
 * the application's own error handling.
 * <p>
 * Only the refusal the protected method's interceptor marked on this request is answered, found as the exception or
 * among its causes. Every other exception, whatever its type, what the application's handlers answered (nothing reaches
 * this filter then), and a response already committed stay as they are. Nothing is read or written but the request
 * attribute, so the request waits for nothing of Contexa's.
 */
public class ProtectableRefusalFilter extends OncePerRequestFilter {

    /** The request attribute that holds the refusal the interceptor threw for this request. */
    public static final String REFUSAL = "ctxa.protectable.refusal";

    private static final int MAX_CAUSES = 16;

    /** At the interceptor: marks the refusal it throws, before the method runs, as its own. */
    public static <T extends RuntimeException> T markRefusal(@Nullable HttpServletRequest request, T refusal) {
        if (request != null) {
            request.setAttribute(REFUSAL, refusal);
        }
        return refusal;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        try {
            chain.doFilter(request, response);
        } catch (ServletException | IOException | RuntimeException failure) {
            Object refusal = request.getAttribute(REFUSAL);
            if (refusal == null || response.isCommitted() || !carries(failure, refusal)) {
                throw failure;
            }
            response.sendError(refusal instanceof AuthenticationException
                    ? HttpServletResponse.SC_UNAUTHORIZED
                    : HttpServletResponse.SC_FORBIDDEN);
        }
    }

    /** Whether the failure is the refusal or carries it among its causes, as Spring Security's translation looks there. */
    private static boolean carries(Throwable failure, Object refusal) {
        Throwable current = failure;
        for (int depth = 0; current != null && depth < MAX_CAUSES; depth++) {
            if (current == refusal) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }
}
