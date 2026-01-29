package io.contexa.contexacore.hcad.filter;

import io.contexa.contexacommon.hcad.domain.HCADAnalysisResult;
import io.contexa.contexacore.hcad.service.HCADAnalysisService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
public class HCADFilter extends OncePerRequestFilter {

    private final HCADAnalysisService hcadAnalysisService;

    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    @Value("${hcad.enabled:true}")
    private boolean enabled;

    public HCADFilter(HCADAnalysisService hcadAnalysisService) {
        this.hcadAnalysisService = hcadAnalysisService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean isAuthenticated = this.trustResolver.isAuthenticated(authentication);

        if (!enabled || !isAuthenticated) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            HCADAnalysisResult result = hcadAnalysisService.analyze(request, authentication);

            if (result.getContext() != null) {
                request.setAttribute("hcad.is_new_session", result.getContext().getIsNewSession());
                request.setAttribute("hcad.is_new_user", result.getContext().getIsNewUser());
                request.setAttribute("hcad.is_new_device", result.getContext().getIsNewDevice());
                request.setAttribute("hcad.recent_request_count", result.getContext().getRecentRequestCount());
            }

            String action = result.getAction();
            if ("BLOCK".equalsIgnoreCase(action) || "ESCALATE".equalsIgnoreCase(action)) {
                log.error("[HCADFilter] Security action: {} - userId: {}, riskScore: {}, threatType: {}",
                    action, result.getUserId(), String.format("%.3f", result.getAnomalyScore()), result.getThreatType());
            }

            filterChain.doFilter(request, response);

        } catch (Exception e) {
            log.error("[HCADFilter] Error during processing", e);
            filterChain.doFilter(request, response);
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/static/") ||
               path.startsWith("/css/") ||
               path.startsWith("/js/") ||
               path.startsWith("/images/") ||
               path.equals("/health") ||
               path.startsWith("/actuator/") ||
               path.startsWith("/api/admin/test/vectorstore");
    }
}
