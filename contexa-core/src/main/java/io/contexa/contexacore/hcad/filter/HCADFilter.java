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
package io.contexa.contexacore.hcad.filter;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.hcad.domain.HCADAnalysisResult;
import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacommon.hcad.official.OfficialContextRequestAttributes;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionAssessment;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionContextResolver;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionRequestProjector;
import io.contexa.contexacore.hcad.service.HCADAnalysisService;
import io.contexa.contexacore.hcad.trigger.HcadRequestPathUtils;
import io.contexa.contexacore.properties.HcadProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.AntPathMatcher;
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
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

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
                HCADContext context = result.getContext();
                projectHcadContext(request, context);
                HcadPreProtectablePromotionAssessment assessment = HcadPreProtectablePromotionContextResolver.resolve(context);
                HcadPreProtectablePromotionRequestProjector.project(request, assessment);
            }

            String action = result.getAction();
            if (ZeroTrustAction.fromString(action).isBlocking()) {
                log.info("[HCADFilter] Security action: {} - userId: {}, riskScore: {}, threatType: {}",
                        action,
                        result.getUserId(),
                        String.format("%.3f", result.getAnomalyScore()),
                        result.getThreatType());
            }

            filterChain.doFilter(request, response);
        } catch (Exception e) {
            log.error("[HCADFilter] Error during processing", e);
            request.setAttribute("hcad.analysisStatus", "FAILED");
            request.setAttribute("hcad.failReason", e.getClass().getSimpleName());
            filterChain.doFilter(request, response);
        }
    }

    private void projectHcadContext(HttpServletRequest request, HCADContext context) {
        request.setAttribute("hcad.is_new_session", context.getIsNewSession());
        request.setAttribute("hcad.is_new_user", context.getIsNewUser());
        request.setAttribute("hcad.is_new_device", context.getIsNewDevice());
        request.setAttribute("hcad.baseline_confidence", context.getBaselineConfidence());
        request.setAttribute("hcad.is_sensitive_resource", context.getIsSensitiveResource());
        request.setAttribute("hcad.previous_path", context.getPreviousPath());
        request.setAttribute("hcad.last_request_interval_ms", context.getLastRequestInterval());
        request.setAttribute("hcad.observed_at", context.getTimestamp());
        if (context.getLatitude() != null) {
            request.setAttribute("hcad.latitude", context.getLatitude());
        }
        if (context.getLongitude() != null) {
            request.setAttribute("hcad.longitude", context.getLongitude());
        }

        OfficialContextRequestAttributes.applySnapshot(
                request,
                OfficialContextRequestAttributes.snapshotFrom(context),
                false);

        Map<String, Object> attrs = context.getAdditionalAttributes();
        if (attrs != null) {
            Object resourceBusinessLabel = attrs.get("resourceBusinessLabel");
            if (resourceBusinessLabel != null) {
                request.setAttribute("hcad.resource_business_label", resourceBusinessLabel);
            }
            if (Boolean.TRUE.equals(attrs.get("impossibleTravel"))) {
                request.setAttribute("hcad.impossibleTravel", true);
                request.setAttribute("hcad.travelDistanceKm", attrs.get("travelDistanceKm"));
                request.setAttribute("hcad.travelElapsedMinutes", attrs.get("travelElapsedMinutes"));
                request.setAttribute("hcad.previousLocation", attrs.get("previousLocation"));
            }
            if (attrs.get("userRoles") != null) {
                request.setAttribute("hcad.user_roles", attrs.get("userRoles").toString());
            }
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = HcadRequestPathUtils.normalizedPath(request);
        return matchesExcludedPattern(path) ||
               HcadRequestPathUtils.isDefaultExcluded(path);
    }

    private boolean matchesExcludedPattern(String path) {
        if (path == null || hcadProperties.getFilter() == null
                || hcadProperties.getFilter().getExcludedPatterns() == null) {
            return false;
        }
        for (String pattern : hcadProperties.getFilter().getExcludedPatterns()) {
            if (pattern != null && !pattern.isBlank()
                    && (path.equals(pattern) || pathMatcher.match(pattern, path))) {
                return true;
            }
        }
        return false;
    }
}
