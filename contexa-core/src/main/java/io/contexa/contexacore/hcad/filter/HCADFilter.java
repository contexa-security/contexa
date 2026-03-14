package io.contexa.contexacore.hcad.filter;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.hcad.domain.HCADAnalysisResult;
import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacore.hcad.service.HCADAnalysisService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import io.contexa.contexacore.properties.HcadProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

@Slf4j
public class HCADFilter extends OncePerRequestFilter {

    private final HCADAnalysisService hcadAnalysisService;
    private final HcadProperties hcadProperties;

    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    public HCADFilter(HCADAnalysisService hcadAnalysisService, HcadProperties hcadProperties) {
        this.hcadAnalysisService = hcadAnalysisService;
        this.hcadProperties = hcadProperties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean isAuthenticated = this.trustResolver.isAuthenticated(authentication);

        if (!hcadProperties.isEnabled() || !isAuthenticated) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            HCADAnalysisResult result = hcadAnalysisService.analyze(request, authentication);

            if (result.getContext() != null) {
                HCADContext ctx = result.getContext();
                request.setAttribute("hcad.is_new_session", ctx.getIsNewSession());
                request.setAttribute("hcad.is_new_user", ctx.getIsNewUser());
                request.setAttribute("hcad.is_new_device", ctx.getIsNewDevice());
                request.setAttribute("hcad.recent_request_count", ctx.getRecentRequestCount());
                request.setAttribute("hcad.failed_login_attempts", ctx.getFailedLoginAttempts());
                request.setAttribute("hcad.baseline_confidence", ctx.getBaselineConfidence());
                request.setAttribute("hcad.is_sensitive_resource", ctx.getIsSensitiveResource());
                request.setAttribute("hcad.mfa_verified", ctx.getHasValidMFA());
                if (ctx.getCountry() != null) {
                    request.setAttribute("hcad.country", ctx.getCountry());
                }
                if (ctx.getCity() != null) {
                    request.setAttribute("hcad.city", ctx.getCity());
                }
                if (ctx.getLatitude() != null) {
                    request.setAttribute("hcad.latitude", ctx.getLatitude());
                }
                if (ctx.getLongitude() != null) {
                    request.setAttribute("hcad.longitude", ctx.getLongitude());
                }
                Map<String, Object> attrs = ctx.getAdditionalAttributes();
                if (attrs != null) {
                    if (Boolean.TRUE.equals(attrs.get("impossibleTravel"))) {
                        request.setAttribute("hcad.impossibleTravel", true);
                        request.setAttribute("hcad.travelDistanceKm", attrs.get("travelDistanceKm"));
                        request.setAttribute("hcad.travelElapsedMinutes", attrs.get("travelElapsedMinutes"));
                        request.setAttribute("hcad.previousLocation", attrs.get("previousLocation"));
                    }
                }
                if (attrs != null && attrs.get("userRoles") != null) {
                    request.setAttribute("hcad.user_roles", attrs.get("userRoles").toString());
                }
            }

            String action = result.getAction();
            if (ZeroTrustAction.fromString(action).isBlocking()) {
                log.error("[HCADFilter] Security action: {} - userId: {}, riskScore: {}, threatType: {}",
                    action, result.getUserId(), String.format("%.3f", result.getAnomalyScore()), result.getThreatType());
            }

            filterChain.doFilter(request, response);

        } catch (Exception e) {
            log.error("[HCADFilter] Error during processing", e);
            request.setAttribute("hcad.analysisStatus", "FAILED");
            request.setAttribute("hcad.failReason", e.getClass().getSimpleName());
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
