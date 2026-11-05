/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaiam.admin.web.auth.filter;

import io.contexa.contexacommon.security.RequestPaths;
import io.contexa.contexacommon.security.ZeroTrustScreens;
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

    private static final String FAVICON_PATH = "/favicon.ico";

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
        String clientIp = null;
        boolean denied = false;
        boolean rejected = false;
        try {
            clientIp = RequestInfoExtractor.extractClientIp(request, securityProperties);
            denied = ipAccessRuleService.isIpDenied(clientIp);
            rejected = !denied && ipAccessRuleService.hasActiveAllowRules() && !ipAccessRuleService.isIpAllowed(clientIp);
        } catch (RuntimeException e) {
            // the rules live in Contexa's database: when they cannot be read the request is not refused for them
            log.warn("IP access rules could not be read; the request goes on: {}", e.toString());
        }
        if (denied) {
            log.error("IP access denied for: {}", clientIp);
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
            return;
        }
        if (rejected) {
            log.error("IP access rejected by allow-list: {}", clientIp);
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
            return;
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Skip static resources
        String path = RequestPaths.of(request);
        return FAVICON_PATH.equals(path) || ZeroTrustScreens.isScreenResource(path);
    }
}
