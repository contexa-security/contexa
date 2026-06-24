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
import io.contexa.contexacore.hcad.projection.HcadTrustedAnchorSignalProbe;
import io.contexa.contexacore.hcad.projection.TrustedHcadContextProjection;
import io.contexa.contexacore.hcad.projection.TrustedHcadContextProjectionFactory;
import io.contexa.contexacore.hcad.semantic.CachedSemanticEvidenceProjection;
import io.contexa.contexacore.hcad.semantic.HcadSemanticEvidenceCache;
import io.contexa.contexacore.hcad.semantic.HcadSemanticEvidenceCacheStatus;
import io.contexa.contexacore.hcad.semantic.HcadSemanticEvidenceEntry;
import io.contexa.contexacore.hcad.semantic.HcadSemanticEvidenceKey;
import io.contexa.contexacore.hcad.semantic.HcadSemanticEvidenceWarmupRequest;
import io.contexa.contexacore.hcad.semantic.HcadSemanticEvidenceWarmupResult;
import io.contexa.contexacore.hcad.semantic.HcadSemanticEvidenceWarmupService;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyEvidenceReport;
import io.contexa.contexacore.hcad.trigger.HcadActorSessionKeyFactory;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyKeyFactory;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyTriggerAttributes;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyTriggerOrchestrator;
import io.contexa.contexacore.hcad.trigger.HcadRequestPathUtils;
import io.contexa.contexacore.hcad.trigger.window.HcadObservationWindowLease;
import io.contexa.contexacore.hcad.trigger.window.HcadObservationWindowRepository;
import io.contexa.contexacore.hcad.trigger.window.HcadRequestObservation;
import io.contexa.contexacore.hcad.trigger.window.InMemoryHcadObservationWindowRepository;
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
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;

@Slf4j
public class HCADFilter extends OncePerRequestFilter {

    private final TrustedHcadContextProjectionFactory trustedProjectionFactory;
    private final HcadPreProtectablePromotionScorer preProtectablePromotionScorer;
    private final Supplier<PendingAnomalyTriggerOrchestrator> pendingAnomalyTriggerOrchestratorSupplier;
    private final Supplier<HcadEvaluationWriter> hcadEvaluationWriterSupplier;
    private final Supplier<HcadSemanticEvidenceCache> semanticEvidenceCacheSupplier;
    private final Supplier<HcadSemanticEvidenceWarmupService> semanticEvidenceWarmupServiceSupplier;
    private final HcadObservationWindowRepository observationWindowRepository;
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
        this.semanticEvidenceCacheSupplier = null;
        this.semanticEvidenceWarmupServiceSupplier = null;
        this.observationWindowRepository = new InMemoryHcadObservationWindowRepository();
    }

    public HCADFilter(
            TrustedHcadContextProjectionFactory trustedProjectionFactory,
            HcadPreProtectablePromotionScorer preProtectablePromotionScorer,
            HcadProperties hcadProperties,
            Supplier<PendingAnomalyTriggerOrchestrator> pendingAnomalyTriggerOrchestratorSupplier,
            Supplier<HcadEvaluationWriter> hcadEvaluationWriterSupplier,
            HcadObservationWindowRepository observationWindowRepository) {
        this(
                trustedProjectionFactory,
                preProtectablePromotionScorer,
                hcadProperties,
                pendingAnomalyTriggerOrchestratorSupplier,
                hcadEvaluationWriterSupplier,
                observationWindowRepository,
                null,
                null);
    }

    public HCADFilter(
            TrustedHcadContextProjectionFactory trustedProjectionFactory,
            HcadPreProtectablePromotionScorer preProtectablePromotionScorer,
            HcadProperties hcadProperties,
            Supplier<PendingAnomalyTriggerOrchestrator> pendingAnomalyTriggerOrchestratorSupplier,
            Supplier<HcadEvaluationWriter> hcadEvaluationWriterSupplier,
            HcadObservationWindowRepository observationWindowRepository,
            Supplier<HcadSemanticEvidenceCache> semanticEvidenceCacheSupplier) {
        this(
                trustedProjectionFactory,
                preProtectablePromotionScorer,
                hcadProperties,
                pendingAnomalyTriggerOrchestratorSupplier,
                hcadEvaluationWriterSupplier,
                observationWindowRepository,
                semanticEvidenceCacheSupplier,
                null);
    }

    public HCADFilter(
            TrustedHcadContextProjectionFactory trustedProjectionFactory,
            HcadPreProtectablePromotionScorer preProtectablePromotionScorer,
            HcadProperties hcadProperties,
            Supplier<PendingAnomalyTriggerOrchestrator> pendingAnomalyTriggerOrchestratorSupplier,
            Supplier<HcadEvaluationWriter> hcadEvaluationWriterSupplier,
            HcadObservationWindowRepository observationWindowRepository,
            Supplier<HcadSemanticEvidenceCache> semanticEvidenceCacheSupplier,
            Supplier<HcadSemanticEvidenceWarmupService> semanticEvidenceWarmupServiceSupplier) {
        this.trustedProjectionFactory = trustedProjectionFactory;
        this.preProtectablePromotionScorer = preProtectablePromotionScorer;
        this.hcadProperties = hcadProperties;
        this.pendingAnomalyTriggerOrchestratorSupplier = pendingAnomalyTriggerOrchestratorSupplier;
        this.hcadEvaluationWriterSupplier = hcadEvaluationWriterSupplier;
        this.semanticEvidenceCacheSupplier = semanticEvidenceCacheSupplier;
        this.semanticEvidenceWarmupServiceSupplier = semanticEvidenceWarmupServiceSupplier;
        this.observationWindowRepository = observationWindowRepository == null
                ? new InMemoryHcadObservationWindowRepository()
                : observationWindowRepository;
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
            String actorSessionKey = HcadActorSessionKeyFactory.fromRequest(request, authentication);
            trustedProjectionFactory.recordLightweightRequestCounter(request, authentication);
            HcadObservationWindowLease windowLease = observeRequest(actorSessionKey, request);
            request.setAttribute("hcad.actorSessionKey", actorSessionKey);
            request.setAttribute("hcad.windowId", windowLease.windowId());
            request.setAttribute("hcad.windowRequestCount", windowLease.requestCount());
            boolean nonUserInteraction = HcadRequestPathUtils.isNonUserInteractionRequest(request);
            boolean deepEvaluationOwner = windowLease.deepEvaluationOwner();
            HcadTrustedAnchorSignalProbe anchorProbe = nonUserInteraction
                    ? null
                    : trustedProjectionFactory.probeAnchorSignals(request, authentication);
            String trustedContextSignature = trustedContextSignature(anchorProbe);
            if (!deepEvaluationOwner && !nonUserInteraction) {
                if (anchorProbe != null
                        && anchorProbe.hasReEvaluationSignature()
                        && observationWindowRepository.tryAcquireEscalation(
                        actorSessionKey,
                        windowLease.windowId(),
                        anchorProbe.reEvaluationSignature())) {
                    deepEvaluationOwner = true;
                    request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_ESCALATION_EVALUATION, true);
                    request.setAttribute("hcad.reEvaluationSignals", anchorProbe.reEvaluationSignals());
                    request.setAttribute("hcad.reEvaluationSignature", anchorProbe.reEvaluationSignature());
                    windowLease = new HcadObservationWindowLease(
                            true,
                            windowLease.actorSessionKey(),
                            windowLease.windowId(),
                            windowLease.requestCount(),
                            windowLease.resourceFamilies(),
                            windowLease.samplePaths());
                }
            }
            if (deepEvaluationOwner && !nonUserInteraction
                    && !observationWindowRepository.tryAcquireActorSessionEvaluation(
                    actorSessionKey,
                    trustedContextSignature,
                    actorSessionEvaluationTtl())) {
                request.setAttribute("hcad.actorSessionEvaluationSuppressed", true);
                request.setAttribute("hcad.actorSessionEvaluationSignature", trustedContextSignature);
                trustedProjectionFactory.recordLightweightSessionNarrative(request, authentication);
                updateWindowObservation(actorSessionKey, windowLease);
                if (log.isTraceEnabled()) {
                    log.trace("[HCADFilter] Actor-session TTL suppressed deep evaluation: actorSessionKey={}, windowId={}, path={}, signature={}",
                            actorSessionKey,
                            windowLease.windowId(),
                            HcadRequestPathUtils.normalizedPath(request),
                            trustedContextSignature);
                }
                filterChain.doFilter(request, response);
                return;
            }
            if (!deepEvaluationOwner || nonUserInteraction) {
                trustedProjectionFactory.recordLightweightSessionNarrative(request, authentication);
                updateWindowObservation(actorSessionKey, windowLease);
                if (log.isTraceEnabled()) {
                    log.trace("[HCADFilter] Observation-only request: actorSessionKey={}, windowId={}, path={}, owner={}",
                            actorSessionKey,
                            windowLease.windowId(),
                            HcadRequestPathUtils.normalizedPath(request),
                            windowLease.deepEvaluationOwner());
                }
                filterChain.doFilter(request, response);
                return;
            }

            TrustedHcadContextProjection projection = trustedProjectionFactory.project(request, authentication);
            CachedSemanticEvidenceProjection semanticEvidence = semanticEvidenceCacheSupplier == null
                    ? null
                    : resolveSemanticEvidence(request, projection);
            HcadPreProtectablePromotionAssessment assessment = semanticEvidence == null
                    ? preProtectablePromotionScorer.score(projection)
                    : preProtectablePromotionScorer.score(projection, semanticEvidence);
            String projectedActorSessionKey = HcadActorSessionKeyFactory.fromProjection(projection);
            windowLease = observationWindowRepository
                    .snapshot(actorSessionKey, windowLease.windowId())
                    .orElse(windowLease);
            request.setAttribute("hcad.windowRequestCount", windowLease.requestCount());
            assessment = withWindowMetadata(
                    request,
                    projection,
                    assessment,
                    semanticEvidence,
                    windowLease,
                    firstText(projectedActorSessionKey, actorSessionKey),
                    trustedContextSignature);
            observationWindowRepository.markDeepEvaluationCompleted(
                    actorSessionKey,
                    windowLease.windowId(),
                    PendingAnomalyKeyFactory.buildTrustedAnchorSignature(assessment.anchorSignals()));
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

    private HcadObservationWindowLease observeRequest(String actorSessionKey, HttpServletRequest request) {
        HcadRequestObservation observation = new HcadRequestObservation(
                request != null ? request.getHeader("X-Request-Id") : null,
                request != null ? request.getMethod() : null,
                HcadRequestPathUtils.normalizedPath(request),
                HcadRequestPathUtils.resourceFamily(HcadRequestPathUtils.normalizedPath(request)),
                Instant.now());
        Duration coalesceWindow = Duration.ofMillis(Math.max(1L, hcadProperties.getPreTrigger().getCoalesceWindowMs()));
        Duration observationTtl = Duration.ofSeconds(Math.max(
                hcadProperties.getPreTrigger().getEvaluationTtlSeconds(),
                hcadProperties.getPreTrigger().getObservationTtlSeconds()));
        return observationWindowRepository.observe(
                actorSessionKey,
                observation,
                coalesceWindow,
                observationTtl);
    }

    private CachedSemanticEvidenceProjection resolveSemanticEvidence(
            HttpServletRequest request,
            TrustedHcadContextProjection projection) {
        HcadSemanticEvidenceCache cache = semanticEvidenceCacheSupplier == null
                ? null
                : semanticEvidenceCacheSupplier.get();
        if (cache == null || projection == null) {
            return CachedSemanticEvidenceProjection.unavailable("SEMANTIC_EVIDENCE_CACHE_UNAVAILABLE");
        }
        HcadProperties.SemanticEvidenceSettings.EvidenceCacheProvider provider = cache.provider();
        if (request != null && provider != null) {
            request.setAttribute("hcad.semanticEvidenceCacheProvider", provider.name());
        }
        List<HcadSemanticEvidenceEntry> entries = new ArrayList<>();
        List<String> gaps = new ArrayList<>();
        for (HcadSemanticEvidenceKey key : semanticEvidenceKeys(projection)) {
            SemanticEvidenceLookup lookup = lookupSemanticEvidence(cache, key);
            if (lookup.gapCode() != null) {
                gaps.add(lookup.gapCode());
                if (lookup.terminalFailure()) {
                    continue;
                }
            }
            Optional<HcadSemanticEvidenceEntry> entry = lookup.entry();
            if (entry.isPresent()) {
                entries.add(entry.get());
                if (entry.get().status().sourceAbsent() && request != null) {
                    request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_NEGATIVE_CACHE_HIT, true);
                }
                if (entry.get().status() == HcadSemanticEvidenceCacheStatus.VERSION_MISMATCH
                        || entry.get().status() == HcadSemanticEvidenceCacheStatus.DIMENSION_MISMATCH) {
                    HcadSemanticEvidenceWarmupResult warmupResult =
                            requestSemanticEvidenceWarmup(projection, cache, key);
                    appendWarmupGaps(gaps, warmupResult);
                }
            } else {
                gaps.add("SEMANTIC_EVIDENCE_CACHE_MISS");
                HcadSemanticEvidenceWarmupResult warmupResult = requestSemanticEvidenceWarmup(projection, cache, key);
                appendWarmupGaps(gaps, warmupResult);
            }
        }
        CachedSemanticEvidenceProjection projectionEvidence = CachedSemanticEvidenceProjection.of(entries);
        if (gaps.isEmpty()) {
            return projectionEvidence;
        }
        List<String> mergedGaps = new ArrayList<>(projectionEvidence.evidenceGapCodes());
        mergedGaps.addAll(gaps);
        return new CachedSemanticEvidenceProjection(entries, mergedGaps);
    }

    private SemanticEvidenceLookup lookupSemanticEvidence(
            HcadSemanticEvidenceCache cache,
            HcadSemanticEvidenceKey key) {
        if (cache == null || key == null) {
            return SemanticEvidenceLookup.empty("SEMANTIC_EVIDENCE_CACHE_UNAVAILABLE", true);
        }
        int timeoutMs = hcadProperties == null || hcadProperties.getSemanticEvidence() == null
                ? 0
                : hcadProperties.getSemanticEvidence().getLookupTimeoutMs();
        HcadProperties.SemanticEvidenceSettings.EvidenceCacheProvider provider = cache.provider();
        if (provider != HcadProperties.SemanticEvidenceSettings.EvidenceCacheProvider.REDIS
                || timeoutMs <= 0) {
            try {
                return new SemanticEvidenceLookup(cache.get(key), null, false);
            } catch (RuntimeException ex) {
                log.debug("[HCAD] semantic evidence lookup failed: type={}, resourceId={}",
                        key.type(), key.resourceId(), ex);
                return SemanticEvidenceLookup.empty("SEMANTIC_EVIDENCE_LOOKUP_FAILED", true);
            }
        }
        CompletableFuture<Optional<HcadSemanticEvidenceEntry>> lookup =
                CompletableFuture.supplyAsync(() -> cache.get(key));
        try {
            return new SemanticEvidenceLookup(lookup.get(timeoutMs, TimeUnit.MILLISECONDS), null, false);
        } catch (TimeoutException ex) {
            lookup.cancel(true);
            return SemanticEvidenceLookup.empty("SEMANTIC_EVIDENCE_LOOKUP_TIMEOUT", true);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            return SemanticEvidenceLookup.empty("SEMANTIC_EVIDENCE_LOOKUP_FAILED", true);
        } catch (ExecutionException | RuntimeException ex) {
            return SemanticEvidenceLookup.empty("SEMANTIC_EVIDENCE_LOOKUP_FAILED", true);
        }
    }

    private void appendWarmupGaps(List<String> gaps, HcadSemanticEvidenceWarmupResult warmupResult) {
        if (gaps == null || warmupResult == null) {
            return;
        }
        if (warmupResult.status() != null) {
            gaps.add(warmupResult.status().name());
        }
        if (warmupResult.reasonCode() != null) {
            gaps.add(warmupResult.reasonCode());
        }
    }

    private HcadSemanticEvidenceWarmupResult requestSemanticEvidenceWarmup(
            TrustedHcadContextProjection projection,
            HcadSemanticEvidenceCache cache,
            HcadSemanticEvidenceKey key) {
        HcadSemanticEvidenceWarmupService warmupService = semanticEvidenceWarmupServiceSupplier == null
                ? null
                : semanticEvidenceWarmupServiceSupplier.get();
        if (warmupService == null) {
            return HcadSemanticEvidenceWarmupResult.unavailable("WARMUP_SERVICE_UNAVAILABLE");
        }
        return warmupService.requestWarmup(new HcadSemanticEvidenceWarmupRequest(projection, key), cache);
    }

    private List<HcadSemanticEvidenceKey> semanticEvidenceKeys(TrustedHcadContextProjection projection) {
        if (projection == null) {
            return List.of();
        }
        String resourceId = HcadRequestPathUtils.resourceFamily(projection.normalizedPath());
        HcadProperties.SemanticEvidenceSettings settings = hcadProperties.getSemanticEvidence();
        int dimension = Math.max(1, hcadProperties.getVector().getEmbeddingDimension());
        return List.of(
                HcadSemanticEvidenceKey.normalRequestSimilarity(
                        projection.tenantId(),
                        projection.userId(),
                        resourceId,
                        settings.getBaselineVersion(),
                        settings.getEmbeddingModel(),
                        dimension,
                        settings.getEvidenceVersion()),
                HcadSemanticEvidenceKey.riskRequestSimilarity(
                        projection.tenantId(),
                        projection.userId(),
                        resourceId,
                        firstText(projection.authorizationPolicyId(), "policy-unknown"),
                        firstText(projection.promptContextContractVersion(), "prompt-unknown"),
                        settings.getEmbeddingModel(),
                        dimension,
                        settings.getEvidenceVersion()));
    }

    private record SemanticEvidenceLookup(
            Optional<HcadSemanticEvidenceEntry> entry,
            String gapCode,
            boolean terminalFailure) {

        private SemanticEvidenceLookup {
            entry = entry == null ? Optional.empty() : entry;
        }

        static SemanticEvidenceLookup empty(String gapCode, boolean terminalFailure) {
            return new SemanticEvidenceLookup(Optional.empty(), gapCode, terminalFailure);
        }
    }

    private void updateWindowObservation(String actorSessionKey, HcadObservationWindowLease windowLease) {
        HcadEvaluationWriter writer = hcadEvaluationWriterSupplier == null ? null : hcadEvaluationWriterSupplier.get();
        if (writer == null || windowLease == null) {
            return;
        }
        HcadObservationWindowLease latest = observationWindowRepository
                .snapshot(actorSessionKey, windowLease.windowId())
                .orElse(windowLease);
        writer.updateWindowObservation(actorSessionKey, windowLease.windowId(), latest);
    }

    private HcadPreProtectablePromotionAssessment withWindowMetadata(
            HttpServletRequest request,
            TrustedHcadContextProjection projection,
            HcadPreProtectablePromotionAssessment assessment,
            CachedSemanticEvidenceProjection semanticEvidence,
            HcadObservationWindowLease windowLease,
            String actorSessionKey,
            String trustedContextSignature) {
        if (assessment == null) {
            return null;
        }
        Map<String, Object> rawSignals = new LinkedHashMap<>(assessment.rawSignalSnapshot());
        rawSignals.put("actorSessionKey", actorSessionKey);
        rawSignals.put("windowId", windowLease.windowId());
        rawSignals.put("triggerScope", "SESSION_WINDOW");
        rawSignals.put("requestCount", windowLease.requestCount());
        rawSignals.put("duplicateSuppressedCount", windowLease.duplicateSuppressedCount());
        rawSignals.put("resourceFamilies", windowLease.resourceFamilies());
        rawSignals.put("samplePaths", windowLease.samplePaths());
        rawSignals.put("coalesceWindowMs", hcadProperties.getPreTrigger().getCoalesceWindowMs());
        rawSignals.put("actorSessionEvaluationTtl",
                hcadProperties.getPreTrigger().getActorSessionEvaluationTtlSeconds() + "s");
        rawSignals.put("actorSessionEvaluationSignature", trustedContextSignature);
        rawSignals.put("observationWindowTtl", hcadProperties.getPreTrigger().getEvaluationTtlSeconds() + "s");
        rawSignals.put("observationTtl", hcadProperties.getPreTrigger().getObservationTtlSeconds() + "s");
        Object semanticEvidenceCacheProvider = request == null
                ? null
                : request.getAttribute("hcad.semanticEvidenceCacheProvider");
        if (semanticEvidenceCacheProvider != null) {
            rawSignals.put("semanticEvidenceCacheProvider", semanticEvidenceCacheProvider);
        }
        putSemanticEvidenceFreshness(rawSignals, semanticEvidence);
        if (projection != null) {
            rawSignals.put("tenantId", projection.tenantId());
            rawSignals.put("organizationId", projection.organizationId());
        }
        return new HcadPreProtectablePromotionAssessment(
                assessment.score(),
                assessment.band(),
                assessment.eligible(),
                assessment.anchorSignals(),
                assessment.corroboratingSignals(),
                assessment.reasonCodes(),
                assessment.summary(),
                assessment.evaluationVersion(),
                rawSignals);
    }

    private void putSemanticEvidenceFreshness(
            Map<String, Object> rawSignals,
            CachedSemanticEvidenceProjection semanticEvidence) {
        if (rawSignals == null || semanticEvidence == null || semanticEvidence.entries().isEmpty()) {
            return;
        }
        List<Map<String, Object>> entries = new ArrayList<>();
        Instant latestExpiresAt = null;
        for (HcadSemanticEvidenceEntry entry : semanticEvidence.entries()) {
            if (entry == null) {
                continue;
            }
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("type", entry.key().type().name());
            item.put("status", entry.status().name());
            item.put("createdAt", entry.createdAt() == null ? null : entry.createdAt().toString());
            item.put("expiresAt", entry.expiresAt() == null ? null : entry.expiresAt().toString());
            item.put("sourceVersion", entry.sourceVersion());
            item.put("evidenceVersion", entry.evidenceVersion());
            item.put("embeddingModel", entry.embeddingModel());
            item.put("dimension", entry.dimension());
            entries.add(item);
            if (entry.expiresAt() != null
                    && (latestExpiresAt == null || entry.expiresAt().isAfter(latestExpiresAt))) {
                latestExpiresAt = entry.expiresAt();
            }
        }
        if (!entries.isEmpty()) {
            rawSignals.put("semanticEvidenceFreshnessEntries", entries);
        }
        if (latestExpiresAt != null) {
            rawSignals.put("semanticEvidenceExpiresAt", latestExpiresAt.toString());
            rawSignals.put("semanticEvidenceTtl", "entry-specific");
        }
    }

    private Duration actorSessionEvaluationTtl() {
        return Duration.ofSeconds(Math.max(1, hcadProperties.getPreTrigger().getActorSessionEvaluationTtlSeconds()));
    }

    private String trustedContextSignature(HcadTrustedAnchorSignalProbe anchorProbe) {
        List<String> signatureParts = new ArrayList<>();
        if (anchorProbe != null && anchorProbe.hasReEvaluationSignature()) {
            signatureParts.add(anchorProbe.reEvaluationSignature());
        } else {
            signatureParts.add("NO_TRUSTED_ANCHOR_SIGNAL");
        }
        HcadProperties.SemanticEvidenceSettings semantic = hcadProperties.getSemanticEvidence();
        HcadProperties.VectorSettings vector = hcadProperties.getVector();
        if (semantic != null) {
            signatureParts.add("SEMANTIC_VERSION:" + firstText(semantic.getEvidenceVersion(), "unknown"));
            signatureParts.add("SEMANTIC_MODEL:" + firstText(semantic.getEmbeddingModel(), "unknown"));
        }
        if (vector != null) {
            signatureParts.add("EMBEDDING_DIMENSION:" + Math.max(1, vector.getEmbeddingDimension()));
        }
        return PendingAnomalyKeyFactory.buildTrustedAnchorSignature(signatureParts);
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
            refreshRecordedWindowObservation(assessment);
            return;
        }
        recordCandidateWithoutPublisher(request, projection, assessment);
    }

    private void recordCandidateWithoutPublisher(
            HttpServletRequest request,
            TrustedHcadContextProjection projection,
            HcadPreProtectablePromotionAssessment assessment) {
        HcadEvaluationWriter writer = hcadEvaluationWriterSupplier == null ? null : hcadEvaluationWriterSupplier.get();
        if (writer == null || projection == null || assessment == null) {
            return;
        }
        if (!shouldPersistEvaluation(assessment)) {
            return;
        }
        String requestPath = projection.normalizedPath();
        String method = projection.method();
        String riskSignature = PendingAnomalyKeyFactory.buildTrustedSignalSignature(
                assessment.anchorSignals(),
                assessment.corroboratingSignals());
        String actorSessionKey = firstText(
                valueAsText(assessment.rawSignalSnapshot().get("actorSessionKey")),
                HcadActorSessionKeyFactory.fromProjection(projection));
        String triggerStateKey = PendingAnomalyKeyFactory.buildActorSessionDedupKey(actorSessionKey, riskSignature);
        PendingAnomalyEvidenceReport report = new PendingAnomalyEvidenceReport(
                assessment.eligible(),
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
                assessment.eligible(),
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
            if (Boolean.TRUE.equals(request.getAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_NEGATIVE_CACHE_HIT))) {
                writer.markNegativeCacheHit(evaluationId);
            }
            refreshRecordedWindowObservation(assessment);
        }
    }

    private boolean shouldPersistEvaluation(HcadPreProtectablePromotionAssessment assessment) {
        if (assessment == null) {
            return false;
        }
        return assessment.eligible();
    }

    private void refreshRecordedWindowObservation(HcadPreProtectablePromotionAssessment assessment) {
        HcadEvaluationWriter writer = hcadEvaluationWriterSupplier == null ? null : hcadEvaluationWriterSupplier.get();
        if (writer == null || assessment == null || assessment.rawSignalSnapshot() == null) {
            return;
        }
        String actorSessionKey = valueAsText(assessment.rawSignalSnapshot().get("actorSessionKey"));
        String windowId = valueAsText(assessment.rawSignalSnapshot().get("windowId"));
        if (actorSessionKey == null || windowId == null) {
            return;
        }
        observationWindowRepository
                .snapshot(actorSessionKey, windowId)
                .ifPresent(latest -> writer.updateWindowObservation(actorSessionKey, windowId, latest));
    }

    private String firstText(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }

    private String valueAsText(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString();
        return text.isBlank() ? null : text.trim();
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = HcadRequestPathUtils.normalizedPath(request);
        return !hcadProperties.getPreTrigger().shouldEvaluate() ||
               HcadRequestPathUtils.isNonActionableMonitoringPath(path) ||
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
