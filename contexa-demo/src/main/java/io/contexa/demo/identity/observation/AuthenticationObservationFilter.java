package io.contexa.demo.identity.observation;

import io.contexa.demo.configuration.properties.LabProperties;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.identity.observation.dto.AuthenticationHttpObservation;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

@Component
public class AuthenticationObservationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationObservationFilter.class);
    private final AuthenticationObservationSink sink;
    private final LabProperties lab;
    private final DocumentCodec documents;

    public AuthenticationObservationFilter(AuthenticationObservationSink sink, LabProperties lab,
            DocumentCodec documents) {
        this.sink = sink;
        this.lab = lab;
        this.documents = documents;
    }

    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return !(path.equals("/login") || path.equals("/logout") || path.startsWith("/mfa/") ||
                path.startsWith("/api/lab/access"));
    }

    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws
            IOException, ServletException {
        UUID id = UUID.randomUUID();
        boolean before = authenticated(SecurityContextHolder.getContext().getAuthentication());
        response.setHeader("X-Lab-Request-Id", id.toString());
        try {
            chain.doFilter(request, response);
        } finally {
            var current = SecurityContextHolder.getContext().getAuthentication();
            boolean after = authenticated(current);
            try {
                sink.record(
                        new AuthenticationHttpObservation(id, lab.role(), request.getMethod(), request.getServletPath(),
                                Instant.now(),
                                response.getStatus(), before, after, after ? current.getName() : null,
                                after ? current.getClass().getSimpleName() : null,
                                request.getSession(false) == null ? null
                                        : documents.hash(request.getSession(false).getId())));
            } catch (RuntimeException failure) {
                log.warn("Authentication evidence unavailable: {}", failure.getClass().getSimpleName());
            }
        }
    }

    private boolean authenticated(Authentication auth) {
        return auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken);
    }
}
