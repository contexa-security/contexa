package io.contexa.demo.entry.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.demo.configuration.properties.LabProperties;
import io.contexa.demo.entry.configuration.EntryProperties;
import io.contexa.demo.entry.domain.Visitor;
import io.contexa.demo.entry.repository.EntryReadRepository;
import io.contexa.demo.entry.token.VisitorTokens;
import io.contexa.demo.workspace.configuration.WorkspaceAccessProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.util.Map;
import java.util.Set;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 19)
public class EntryGateFilter extends OncePerRequestFilter {

    private static final Set<String> PUBLIC_API = Set.of("/api/auth/csrf", "/api/lab/identity",
            "/api/lab/readiness", "/api/lab/readiness/local");
    private final EntryReadRepository store;
    private final VisitorTokens cookies;
    private final ObjectMapper mapper;
    private final String entryUrl;
    private final WorkspaceAccessProperties workspaces;

    public EntryGateFilter(EntryReadRepository store, VisitorTokens cookies, ObjectMapper mapper,
            EntryProperties properties, LabProperties lab, WorkspaceAccessProperties workspaces) {
        this.store = store;
        this.cookies = cookies;
        this.mapper = mapper;
        this.workspaces = workspaces;
        URI portal = URI.create(properties.portalUrl());
        if (portal.getHost() == null || !Set.of("http", "https").contains(portal.getScheme())
                || portal.getUserInfo() != null || portal.getQuery() != null || portal.getFragment() != null) {
            throw new IllegalArgumentException("Invalid entry portal URL");
        }
        this.entryUrl = "portal".equals(lab.role()) ? "/entry.html" : portal.resolve("/entry.html").toString();
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if ("OPTIONS".equals(request.getMethod())) {
            return true;
        }
        String path = request.getServletPath();
        if (workspaces.enabled() && !entryUrl.equals("/entry.html")
                && (path.equals("/api/lab/identity") || path.equals("/api/auth/csrf"))) {
            return false;
        }
        if (("GET".equals(request.getMethod()) || "HEAD".equals(request.getMethod()))
                && (path.equals("/api/lab/scenarios") || path.startsWith("/api/lab/scenarios/"))) {
            return true;
        }
        if (PUBLIC_API.contains(path) || path.startsWith("/api/lab/entry/")) {
            return true;
        }
        return !(path.equals("/login") || path.equals("/logout")
                || path.startsWith("/api/") || path.startsWith("/mfa/") || path.startsWith("/webauthn/")
                || path.startsWith("/ott/") || path.startsWith("/login/"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Visitor visitor;
        try {
            visitor = store.find(cookies.hash(cookies.read(request)), false);
        } catch (RuntimeException unavailable) {
            reject(response, 503, "ENTRY_STORE_UNAVAILABLE");
            return;
        }
        if (visitor != null && visitor.verified()) {
            request.setAttribute(Visitor.class.getName(), visitor);
            chain.doFilter(request, response);
            return;
        }
        if ("GET".equals(request.getMethod()) && !request.getServletPath().startsWith("/api/")) {
            response.setHeader("Cache-Control", "no-store");
            response.sendRedirect(entryUrl);
        } else {
            reject(response, 403, "EMAIL_VERIFICATION_REQUIRED");
        }
    }

    private void reject(HttpServletResponse response, int status, String state) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-store");
        mapper.writeValue(response.getWriter(), Map.of("state", state, "entryUrl", entryUrl));
    }
}
