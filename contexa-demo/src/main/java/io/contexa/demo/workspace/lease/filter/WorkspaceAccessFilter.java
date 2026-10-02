package io.contexa.demo.workspace.lease.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.demo.configuration.properties.LabProperties;
import io.contexa.demo.entry.domain.Visitor;
import io.contexa.demo.workspace.budget.dto.WorkspaceBudgetKind;
import io.contexa.demo.workspace.budget.service.WorkspaceBudgetService;
import io.contexa.demo.workspace.configuration.WorkspaceAccessProperties;
import io.contexa.demo.workspace.lease.service.WorkspaceLeaseService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.util.Map;
import java.util.UUID;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class WorkspaceAccessFilter extends OncePerRequestFilter {

    private final WorkspaceAccessProperties properties;
    private final LabProperties lab;
    private final WorkspaceLeaseService leases;
    private final WorkspaceBudgetService budgets;
    private final ObjectMapper mapper;

    public WorkspaceAccessFilter(WorkspaceAccessProperties properties, LabProperties lab,
            WorkspaceLeaseService leases, WorkspaceBudgetService budgets, ObjectMapper mapper) {
        this.properties = properties;
        this.lab = lab;
        this.leases = leases;
        this.budgets = budgets;
        this.mapper = mapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if (!properties.enabled() || "portal".equals(lab.role()) || "OPTIONS".equals(request.getMethod())) {
            return true;
        }
        String path = request.getServletPath();
        if (path.startsWith("/api/lab/entry/") || path.startsWith("/api/lab/scenarios")
                || path.startsWith("/api/lab/readiness")) {
            return true;
        }
        return !(path.startsWith("/api/") || path.equals("/login") || path.equals("/logout")
                || path.startsWith("/login/") || path.startsWith("/mfa/") || path.startsWith("/ott/")
                || path.startsWith("/webauthn/"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Visitor visitor = (Visitor) request.getAttribute(Visitor.class.getName());
        if (visitor == null || !visitor.verified()) {
            reject(response, 403, "EMAIL_VERIFICATION_REQUIRED");
            return;
        }
        try {
            var lease = leases.requireWorker(visitor.id());
            if (request.getServletPath().startsWith("/api/work/")) {
                budgets.require(lease.workspaceId(), WorkspaceBudgetKind.WORK, UUID.randomUUID(), null);
            }
        } catch (ResponseStatusException denied) {
            reject(response, denied.getStatusCode().value(), denied.getReason());
            return;
        } catch (RuntimeException unavailable) {
            reject(response, 503, "WORKSPACE_STORE_UNAVAILABLE");
            return;
        }
        chain.doFilter(request, response);
    }

    private void reject(HttpServletResponse response, int status, String state) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-store");
        mapper.writeValue(response.getWriter(), Map.of("state", state, "workspaceUrl", "/workspace.html"));
    }
}
