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
 * <p>The filter runs with the lowest possible precedence in the servlet chain so that any
 * downstream filter (security, authentication) finishes before the cleanup fires.</p>
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
