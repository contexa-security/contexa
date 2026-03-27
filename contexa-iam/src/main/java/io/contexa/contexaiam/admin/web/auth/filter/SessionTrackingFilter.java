package io.contexa.contexaiam.admin.web.auth.filter;

import io.contexa.contexaiam.admin.web.auth.service.SessionManagementService;
import io.contexa.contexaiam.domain.entity.ActiveSession;
import io.contexa.contexaiam.repository.ActiveSessionRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Tracks authenticated sessions and enforces forced invalidation.
 * On each authenticated request:
 * 1. Checks if session is marked as expired in DB -> forces HTTP session invalidation
 * 2. Tracks session activity for monitoring
 */
@RequiredArgsConstructor
public class SessionTrackingFilter extends OncePerRequestFilter {

    private final SessionManagementService sessionManagementService;
    private final ActiveSessionRepository activeSessionRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Check for forced invalidation before processing request
        HttpSession session = request.getSession(false);
        if (session != null) {
            ActiveSession tracked = activeSessionRepository.findById(session.getId()).orElse(null);
            if (tracked != null && tracked.isExpired()) {
                session.invalidate();
                SecurityContextHolder.clearContext();
                response.sendRedirect("/admin");
                return;
            }
        }

        filterChain.doFilter(request, response);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {
            session = request.getSession(false);
            if (session != null) {
                sessionManagementService.trackSession(
                        session.getId(),
                        auth.getName(),
                        auth.getName(),
                        request.getRemoteAddr(),
                        request.getHeader("User-Agent"));
            }
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri.startsWith("/css/")
                || uri.startsWith("/js/")
                || uri.startsWith("/img/")
                || uri.startsWith("/favicon")
                || uri.startsWith("/webjars/")
                || uri.startsWith("/actuator/");
    }
}
