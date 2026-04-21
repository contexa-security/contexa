package io.contexa.contexaiam.admin.web.auth.filter;

import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexaiam.admin.web.auth.service.IpAccessRuleService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
public class IpAccessFilter extends OncePerRequestFilter {

    private final IpAccessRuleService ipAccessRuleService;
    private final TieredStrategyProperties.Security securityProperties;

    public IpAccessFilter(IpAccessRuleService ipAccessRuleService) {
        this(ipAccessRuleService, new TieredStrategyProperties.Security());
    }

    public IpAccessFilter(IpAccessRuleService ipAccessRuleService,
                          TieredStrategyProperties.Security securityProperties) {
        this.ipAccessRuleService = ipAccessRuleService;
        this.securityProperties = securityProperties != null
                ? securityProperties
                : new TieredStrategyProperties.Security();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String clientIp = RequestInfoExtractor.extractClientIp(request, securityProperties);

        if (ipAccessRuleService.isIpDenied(clientIp)) {
            log.error("IP access denied for: {}", clientIp);
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
            return;
        }

        if (ipAccessRuleService.hasActiveAllowRules() && !ipAccessRuleService.isIpAllowed(clientIp)) {
            log.error("IP access rejected by allow-list: {}", clientIp);
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
            return;
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        // Skip static resources
        return uri.startsWith("/css/") || uri.startsWith("/js/") || uri.startsWith("/img/") || uri.startsWith("/favicon");
    }
}
