package io.contexa.showcase.business.internal;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Accepts requests to the workload management API ({@code /internal/**}) only with a verified internal context.
 * The business API keeps processing unsigned requests (they only lose the engine inputs); the management API does
 * not (docs/showcase/ADR.md ADR-24). Runs right after {@link InternalContextFilter}.
 */
public class InternalApiGuardFilter extends OncePerRequestFilter {

    public static final String INTERNAL_PREFIX = "/internal/";

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith(INTERNAL_PREFIX);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (request.getAttribute(InternalContextAttributes.CONTEXT) instanceof InternalContext) {
            chain.doFilter(request, response);
            return;
        }
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getOutputStream().write("{\"error\":\"INTERNAL_SIGNATURE_REQUIRED\"}".getBytes(StandardCharsets.UTF_8));
    }
}
