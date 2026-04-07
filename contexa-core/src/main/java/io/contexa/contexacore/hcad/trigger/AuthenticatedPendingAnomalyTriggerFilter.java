package io.contexa.contexacore.hcad.trigger;

import io.contexa.contexacore.properties.HcadProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
public class AuthenticatedPendingAnomalyTriggerFilter extends OncePerRequestFilter {

    private final PendingAnomalyTriggerOrchestrator pendingAnomalyTriggerOrchestrator;
    private final HcadProperties hcadProperties;

    public AuthenticatedPendingAnomalyTriggerFilter(
            PendingAnomalyTriggerOrchestrator pendingAnomalyTriggerOrchestrator,
            HcadProperties hcadProperties) {
        this.pendingAnomalyTriggerOrchestrator = pendingAnomalyTriggerOrchestrator;
        this.hcadProperties = hcadProperties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            pendingAnomalyTriggerOrchestrator.maybeTrigger(request, authentication);
        } catch (Exception e) {
            log.error("[AuthenticatedPendingAnomalyTriggerFilter] Failed to evaluate pending anomaly trigger", e);
        }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if (!hcadProperties.isEnabled() || !hcadProperties.getPreTrigger().isEnabled()) {
            return true;
        }

        String path = request.getRequestURI();
        return path.startsWith("/static/")
                || path.startsWith("/css/")
                || path.startsWith("/js/")
                || path.startsWith("/images/")
                || path.equals("/health")
                || path.startsWith("/actuator/")
                || path.startsWith("/api/admin/test/vectorstore");
    }
}
