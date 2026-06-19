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

import io.contexa.contexacore.hcad.evaluation.HcadEvaluationWriter;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionAssessment;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionRequestProjector;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionScorer;
import io.contexa.contexacore.hcad.projection.TrustedHcadContextProjection;
import io.contexa.contexacore.hcad.projection.TrustedHcadContextProjectionFactory;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyEvidenceReport;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyKeyFactory;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyTriggerAttributes;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyTriggerOrchestrator;
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
import java.util.function.Supplier;

@Slf4j
public class HCADFilter extends OncePerRequestFilter {

    private final TrustedHcadContextProjectionFactory trustedProjectionFactory;
    private final HcadPreProtectablePromotionScorer preProtectablePromotionScorer;
    private final Supplier<PendingAnomalyTriggerOrchestrator> pendingAnomalyTriggerOrchestratorSupplier;
    private final Supplier<HcadEvaluationWriter> hcadEvaluationWriterSupplier;
    private final HcadProperties hcadProperties;
    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public HCADFilter(
            TrustedHcadContextProjectionFactory trustedProjectionFactory,
            HcadPreProtectablePromotionScorer preProtectablePromotionScorer,
            HcadProperties hcadProperties) {
        this(trustedProjectionFactory, preProtectablePromotionScorer, hcadProperties,
                (Supplier<PendingAnomalyTriggerOrchestrator>) null);
    }

    public HCADFilter(
            TrustedHcadContextProjectionFactory trustedProjectionFactory,
            HcadPreProtectablePromotionScorer preProtectablePromotionScorer,
            HcadProperties hcadProperties,
            PendingAnomalyTriggerOrchestrator pendingAnomalyTriggerOrchestrator) {
        this(
                trustedProjectionFactory,
                preProtectablePromotionScorer,
                hcadProperties,
                () -> pendingAnomalyTriggerOrchestrator,
                null);
    }

    public HCADFilter(
            TrustedHcadContextProjectionFactory trustedProjectionFactory,
            HcadPreProtectablePromotionScorer preProtectablePromotionScorer,
            HcadProperties hcadProperties,
            Supplier<PendingAnomalyTriggerOrchestrator> pendingAnomalyTriggerOrchestratorSupplier) {
        this(trustedProjectionFactory, preProtectablePromotionScorer, hcadProperties,
                pendingAnomalyTriggerOrchestratorSupplier, null);
    }

    public HCADFilter(
            TrustedHcadContextProjectionFactory trustedProjectionFactory,
            HcadPreProtectablePromotionScorer preProtectablePromotionScorer,
            HcadProperties hcadProperties,
            Supplier<PendingAnomalyTriggerOrchestrator> pendingAnomalyTriggerOrchestratorSupplier,
            Supplier<HcadEvaluationWriter> hcadEvaluationWriterSupplier) {
        this.trustedProjectionFactory = trustedProjectionFactory;
        this.preProtectablePromotionScorer = preProtectablePromotionScorer;
        this.hcadProperties = hcadProperties;
        this.pendingAnomalyTriggerOrchestratorSupplier = pendingAnomalyTriggerOrchestratorSupplier;
        this.hcadEvaluationWriterSupplier = hcadEvaluationWriterSupplier;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean isAuthenticated = this.trustResolver.isAuthenticated(authentication);

        if (!hcadProperties.isEnabled() || !hcadProperties.getPreTrigger().shouldEvaluate() || !isAuthenticated) {
            if (log.isTraceEnabled()) {
                log.trace("[HCADFilter] Skipped: path={}, enabled={}, preTrigger={}, authenticated={}",
                        HcadRequestPathUtils.normalizedPath(request),
                        hcadProperties.isEnabled(),
                        hcadProperties.getPreTrigger().shouldEvaluate(),
                        isAuthenticated);
            }
            filterChain.doFilter(request, response);
            return;
        }

        try {
            TrustedHcadContextProjection projection = trustedProjectionFactory.project(request, authentication);
            HcadPreProtectablePromotionAssessment assessment = preProtectablePromotionScorer.score(projection);
            if (log.isTraceEnabled()) {
                log.trace("[HCADFilter] Evaluated: userId={}, method={}, path={}, previousPath={}, score={}, band={}, eligible={}",
                        projection.userId(),
                        projection.method(),
                        projection.normalizedPath(),
                        projection.previousPath(),
                        assessment.score(),
                        assessment.band().serializedValue(),
                        assessment.eligible());
            }
            HcadPreProtectablePromotionRequestProjector.project(
                    request,
                    assessment,
                    hcadProperties.getPreTrigger().effectiveMode());

            if (assessment.eligible()) {
                log.info("[HCADFilter] Trusted pre-trigger candidate: userId={}, method={}, path={}, score={}, band={}, anchors={}",
                        projection.userId(),
                        projection.method(),
                        projection.normalizedPath(),
                        assessment.score(),
                        assessment.band().serializedValue(),
                        assessment.anchorSignals());
            }
            maybeTriggerPendingAnomaly(request, authentication, projection, assessment);

            filterChain.doFilter(request, response);
        } catch (Exception e) {
            log.error("[HCADFilter] Error during processing", e);
            request.setAttribute("hcad.analysisStatus", "FAILED");
            request.setAttribute("hcad.failReason", e.getClass().getSimpleName());
            filterChain.doFilter(request, response);
        }
    }

    private void maybeTriggerPendingAnomaly(
            HttpServletRequest request,
            Authentication authentication,
            TrustedHcadContextProjection projection,
            HcadPreProtectablePromotionAssessment assessment) {
        PendingAnomalyTriggerOrchestrator pendingAnomalyTriggerOrchestrator =
                pendingAnomalyTriggerOrchestratorSupplier == null
                        ? null
                        : pendingAnomalyTriggerOrchestratorSupplier.get();
        if (request == null) {
            return;
        }
        if (Boolean.TRUE.equals(request.getAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATED))) {
            return;
        }
        request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATED, true);
        if (pendingAnomalyTriggerOrchestrator != null) {
            pendingAnomalyTriggerOrchestrator.maybeTrigger(request, authentication);
            if (request.getAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATION_ID) == null) {
                recordCandidateWithoutPublisher(request, projection, assessment);
            }
            return;
        }
        recordCandidateWithoutPublisher(request, projection, assessment);
    }

    private void recordCandidateWithoutPublisher(
            HttpServletRequest request,
            TrustedHcadContextProjection projection,
            HcadPreProtectablePromotionAssessment assessment) {
        HcadEvaluationWriter writer = hcadEvaluationWriterSupplier == null ? null : hcadEvaluationWriterSupplier.get();
        if (writer == null || projection == null || assessment == null || !assessment.eligible()) {
            return;
        }
        String requestPath = projection.normalizedPath();
        String method = projection.method();
        String riskSignature = PendingAnomalyKeyFactory.buildRiskSignature(
                method,
                requestPath,
                assessment.reasonCodes());
        String triggerStateKey = PendingAnomalyKeyFactory.buildTriggerKey(
                projection.userId(),
                projection.contextBindingHash(),
                method,
                requestPath,
                riskSignature);
        PendingAnomalyEvidenceReport report = new PendingAnomalyEvidenceReport(
                true,
                projection.userId(),
                projection.contextBindingHash(),
                triggerStateKey,
                request != null ? request.getHeader("X-Request-Id") : null,
                projection.sessionId(),
                requestPath,
                method,
                projection.clientIp(),
                assessment.score(),
                assessment.band().serializedValue(),
                true,
                assessment.evaluationVersion(),
                assessment.anchorSignals(),
                assessment.corroboratingSignals(),
                assessment.reasonCodes(),
                assessment.summary(),
                riskSignature,
                assessment.rawSignalSnapshot());
        String evaluationId = writer.recordCandidate(hcadProperties.getPreTrigger().effectiveMode(), report);
        if (evaluationId != null && request != null) {
            request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATION_ID, evaluationId);
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = HcadRequestPathUtils.normalizedPath(request);
        return !hcadProperties.getPreTrigger().shouldEvaluate() ||
               matchesExcludedPattern(path);
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
