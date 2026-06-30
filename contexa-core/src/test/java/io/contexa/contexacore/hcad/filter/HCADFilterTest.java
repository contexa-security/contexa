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
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionAttributes;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionBand;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionScorer;
import io.contexa.contexacore.hcad.projection.HcadBaselineComparison;
import io.contexa.contexacore.hcad.projection.HcadPromptSecurityContextFieldRegistry;
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
import io.contexa.contexacore.hcad.trigger.PendingAnomalyTriggerAttributes;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyTriggerOrchestrator;
import io.contexa.contexacore.hcad.trigger.HcadPreTriggerMode;
import io.contexa.contexacore.hcad.trigger.window.HcadObservationWindowLease;
import io.contexa.contexacore.hcad.trigger.window.InMemoryHcadObservationWindowRepository;
import io.contexa.contexacore.properties.HcadProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class HCADFilterTest {

    @Mock
    private TrustedHcadContextProjectionFactory trustedProjectionFactory;

    @Mock
    private HcadPreProtectablePromotionScorer preProtectablePromotionScorer;

    @Mock
    private PendingAnomalyTriggerOrchestrator pendingAnomalyTriggerOrchestrator;

    @Mock
    private HcadEvaluationWriter hcadEvaluationWriter;

    private HCADFilter hcadFilter;
    private HcadProperties hcadProperties;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockFilterChain filterChain;

    @BeforeEach
    void setUp() {
        hcadProperties = new HcadProperties();
        hcadFilter = new HCADFilter(
                trustedProjectionFactory,
                preProtectablePromotionScorer,
                hcadProperties,
                pendingAnomalyTriggerOrchestrator);
        request = new MockHttpServletRequest();
        request.setRequestURI("/api/test");
        response = new MockHttpServletResponse();
        filterChain = new MockFilterChain();
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("trusted HCAD projection assessment should be projected onto request attributes")
    void doFilterInternal_trustedProjection_storesAssessmentInRequest() throws Exception {
        setAuthenticated();
        TrustedHcadContextProjection projection = projection();
        HcadPreProtectablePromotionAssessment assessment = new HcadPreProtectablePromotionAssessment(
                72,
                HcadPreProtectablePromotionBand.REDLINE,
                true,
                List.of("FAILED_LOGIN_BURST"),
                List.of("REQUEST_BURST"),
                List.of("FAILED_LOGIN_BURST", "REQUEST_BURST"),
                "trusted projection",
                "hcad-promotion-v2-trusted-projection",
                Map.of("earlyAnalysisScore", 72, "signalProvenance", Map.of("failedLoginBurst", "STORE_DERIVED")));

        when(trustedProjectionFactory.project(any(), any())).thenReturn(projection);
        when(preProtectablePromotionScorer.score(projection)).thenReturn(assessment);

        hcadFilter.doFilterInternal(request, response, filterChain);

        assertThat(request.getAttribute(HcadPreProtectablePromotionAttributes.REQUEST_SCORE)).isEqualTo(72);
        assertThat(request.getAttribute(HcadPreProtectablePromotionAttributes.REQUEST_BAND)).isEqualTo("REDLINE");
        assertThat(request.getAttribute(HcadPreProtectablePromotionAttributes.REQUEST_ELIGIBLE)).isEqualTo(true);
        assertThat(request.getAttribute(HcadPreProtectablePromotionAttributes.REQUEST_PROVENANCE)).isNotNull();
        assertThat(request.getAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATED)).isEqualTo(true);
        verify(pendingAnomalyTriggerOrchestrator).maybeTrigger(eq(request), any());
        assertThat(filterChain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("already evaluated request should not trigger pending anomaly twice")
    void doFilterInternal_alreadyEvaluated_doesNotTriggerAgain() throws Exception {
        setAuthenticated();
        request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATED, true);
        TrustedHcadContextProjection projection = projection();
        HcadPreProtectablePromotionAssessment assessment = new HcadPreProtectablePromotionAssessment(
                72,
                HcadPreProtectablePromotionBand.REDLINE,
                true,
                List.of("FAILED_LOGIN_BURST"),
                List.of("REQUEST_BURST"),
                List.of("FAILED_LOGIN_BURST", "REQUEST_BURST"),
                "trusted projection",
                "hcad-promotion-v2-trusted-projection",
                Map.of("earlyAnalysisScore", 72));

        when(trustedProjectionFactory.project(any(), any())).thenReturn(projection);
        when(preProtectablePromotionScorer.score(projection)).thenReturn(assessment);

        hcadFilter.doFilterInternal(request, response, filterChain);

        verify(pendingAnomalyTriggerOrchestrator, never()).maybeTrigger(any(), any());
        assertThat(filterChain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("eligible assessment should be recorded when orchestrator is unavailable")
    void doFilterInternal_missingOrchestrator_recordsCandidateWithWriter() throws Exception {
        setAuthenticated();
        hcadFilter = new HCADFilter(
                trustedProjectionFactory,
                preProtectablePromotionScorer,
                hcadProperties,
                () -> null,
                () -> hcadEvaluationWriter);
        TrustedHcadContextProjection projection = projection();
        HcadPreProtectablePromotionAssessment assessment = new HcadPreProtectablePromotionAssessment(
                75,
                HcadPreProtectablePromotionBand.REDLINE,
                true,
                List.of("IMPOSSIBLE_TRAVEL"),
                List.of("REQUEST_BURST", "RAPID_SEQUENCE", "PREVIOUS_PATH_JUMP"),
                List.of("IMPOSSIBLE_TRAVEL", "REQUEST_BURST", "RAPID_SEQUENCE", "PREVIOUS_PATH_JUMP"),
                "trusted projection",
                "hcad-promotion-v2-trusted-projection",
                Map.of("earlyAnalysisScore", 75));
        when(trustedProjectionFactory.project(any(), any())).thenReturn(projection);
        when(preProtectablePromotionScorer.score(projection)).thenReturn(assessment);
        when(hcadEvaluationWriter.recordCandidate(eq(HcadPreTriggerMode.SHADOW), any())).thenReturn("eval-1");

        hcadFilter.doFilterInternal(request, response, filterChain);

        verify(hcadEvaluationWriter).recordCandidate(eq(HcadPreTriggerMode.SHADOW), any());
        assertThat(request.getAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATION_ID)).isEqualTo("eval-1");
        assertThat(filterChain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("missing orchestrator should not persist low-risk non-trigger HTTP requests")
    void doFilterInternal_missingOrchestrator_doesNotPersistLowRiskWindowWithWriter() throws Exception {
        setAuthenticated();
        hcadFilter = new HCADFilter(
                trustedProjectionFactory,
                preProtectablePromotionScorer,
                hcadProperties,
                () -> null,
                () -> hcadEvaluationWriter);
        TrustedHcadContextProjection projection = projection();
        HcadPreProtectablePromotionAssessment assessment = new HcadPreProtectablePromotionAssessment(
                10,
                HcadPreProtectablePromotionBand.LOW,
                false,
                List.of(),
                List.of("PREVIOUS_PATH_JUMP"),
                List.of("PREVIOUS_PATH_JUMP"),
                "trusted low-risk projection",
                "hcad-promotion-v2-trusted-projection",
                Map.of("earlyAnalysisScore", 10));
        when(trustedProjectionFactory.project(any(), any())).thenReturn(projection);
        when(preProtectablePromotionScorer.score(projection)).thenReturn(assessment);

        hcadFilter.doFilterInternal(request, response, filterChain);

        verify(hcadEvaluationWriter, never()).recordCandidate(any(), any());
        assertThat(request.getAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATION_ID)).isNull();
        assertThat(filterChain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("missing orchestrator should not persist high-risk score when assessment is not trigger eligible")
    void doFilterInternal_missingOrchestrator_doesNotPersistHighRiskNonTriggerWindowWithWriter() throws Exception {
        setAuthenticated();
        hcadFilter = new HCADFilter(
                trustedProjectionFactory,
                preProtectablePromotionScorer,
                hcadProperties,
                () -> null,
                () -> hcadEvaluationWriter);
        TrustedHcadContextProjection projection = projection();
        HcadPreProtectablePromotionAssessment assessment = new HcadPreProtectablePromotionAssessment(
                62,
                HcadPreProtectablePromotionBand.HIGH,
                false,
                List.of(),
                List.of("REQUEST_BURST", "BASELINE_MISMATCH"),
                List.of("REQUEST_BURST", "BASELINE_MISMATCH"),
                "trusted high-risk non-trigger projection",
                "hcad-promotion-v2-trusted-projection",
                Map.of("earlyAnalysisScore", 62));
        when(trustedProjectionFactory.project(any(), any())).thenReturn(projection);
        when(preProtectablePromotionScorer.score(projection)).thenReturn(assessment);

        hcadFilter.doFilterInternal(request, response, filterChain);

        verify(hcadEvaluationWriter, never()).recordCandidate(any(), any());
        assertThat(request.getAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATION_ID)).isNull();
        assertThat(filterChain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("semantic evidence cache hit should be passed to scorer without changing actor window key")
    void doFilterInternal_semanticEvidenceCacheHit_passesProjectionToScorer() throws Exception {
        setAuthenticated();
        HcadSemanticEvidenceCache semanticEvidenceCache = mock(HcadSemanticEvidenceCache.class);
        HcadSemanticEvidenceWarmupService warmupService = mock(HcadSemanticEvidenceWarmupService.class);
        hcadFilter = new HCADFilter(
                trustedProjectionFactory,
                preProtectablePromotionScorer,
                hcadProperties,
                () -> pendingAnomalyTriggerOrchestrator,
                () -> hcadEvaluationWriter,
                new InMemoryHcadObservationWindowRepository(),
                () -> semanticEvidenceCache,
                () -> warmupService);
        TrustedHcadContextProjection projection = projection();
        HcadPreProtectablePromotionAssessment assessment = new HcadPreProtectablePromotionAssessment(
                75,
                HcadPreProtectablePromotionBand.REDLINE,
                true,
                List.of("PRIVILEGED_AUTHORIZATION"),
                List.of("SEMANTIC_RISK_SIMILARITY", "SEMANTIC_EVIDENCE_MISMATCH"),
                List.of("PRIVILEGED_AUTHORIZATION", "SEMANTIC_RISK_SIMILARITY", "SEMANTIC_EVIDENCE_MISMATCH"),
                "semantic evidence projection",
                "hcad-promotion-v2-trusted-projection",
                Map.of("earlyAnalysisScore", 75));
        when(trustedProjectionFactory.project(any(), any())).thenReturn(projection);
        when(semanticEvidenceCache.get(any())).thenReturn(Optional.of(semanticEntry()));
        when(preProtectablePromotionScorer.score(eq(projection), any(CachedSemanticEvidenceProjection.class)))
                .thenReturn(assessment);

        hcadFilter.doFilterInternal(request, response, filterChain);

        ArgumentCaptor<CachedSemanticEvidenceProjection> evidenceCaptor =
                ArgumentCaptor.forClass(CachedSemanticEvidenceProjection.class);
        verify(preProtectablePromotionScorer).score(eq(projection), evidenceCaptor.capture());
        assertThat(evidenceCaptor.getValue().hasUsableEvidence()).isTrue();
        assertThat(evidenceCaptor.getValue().maxSimilarityToRisk()).isEqualTo(0.91d);
        verify(semanticEvidenceCache, times(3)).get(any());
        assertThat(filterChain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("semantic evidence cache miss should remain an evidence gap and should not block HCAD")
    void doFilterInternal_semanticEvidenceCacheMiss_recordsGapOnly() throws Exception {
        setAuthenticated();
        HcadSemanticEvidenceCache semanticEvidenceCache = mock(HcadSemanticEvidenceCache.class);
        HcadSemanticEvidenceWarmupService warmupService = mock(HcadSemanticEvidenceWarmupService.class);
        hcadFilter = new HCADFilter(
                trustedProjectionFactory,
                preProtectablePromotionScorer,
                hcadProperties,
                () -> pendingAnomalyTriggerOrchestrator,
                () -> hcadEvaluationWriter,
                new InMemoryHcadObservationWindowRepository(),
                () -> semanticEvidenceCache,
                () -> warmupService);
        TrustedHcadContextProjection projection = projection();
        HcadPreProtectablePromotionAssessment assessment = new HcadPreProtectablePromotionAssessment(
                10,
                HcadPreProtectablePromotionBand.LOW,
                false,
                List.of(),
                List.of(),
                List.of(),
                "cache miss stays gap-only",
                "hcad-promotion-v2-trusted-projection",
                Map.of("earlyAnalysisScore", 10));
        when(trustedProjectionFactory.project(any(), any())).thenReturn(projection);
        when(semanticEvidenceCache.get(any())).thenReturn(Optional.empty());
        when(warmupService.requestWarmup(any(HcadSemanticEvidenceWarmupRequest.class), eq(semanticEvidenceCache)))
                .thenReturn(HcadSemanticEvidenceWarmupResult.queued());
        when(preProtectablePromotionScorer.score(eq(projection), any(CachedSemanticEvidenceProjection.class)))
                .thenReturn(assessment);

        hcadFilter.doFilterInternal(request, response, filterChain);

        ArgumentCaptor<CachedSemanticEvidenceProjection> evidenceCaptor =
                ArgumentCaptor.forClass(CachedSemanticEvidenceProjection.class);
        verify(preProtectablePromotionScorer).score(eq(projection), evidenceCaptor.capture());
        assertThat(evidenceCaptor.getValue().hasUsableEvidence()).isFalse();
        assertThat(evidenceCaptor.getValue().evidenceGapCodes())
                .contains("SEMANTIC_EVIDENCE_CACHE_MISS", "WARMUP_QUEUED");
        verify(semanticEvidenceCache, times(3)).get(any());
        verify(semanticEvidenceCache, never()).put(any(), any());
        verify(warmupService, times(3)).requestWarmup(any(HcadSemanticEvidenceWarmupRequest.class), eq(semanticEvidenceCache));
        assertThat(filterChain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("semantic evidence lookup timeout should be recorded without blocking or warming up")
    void doFilterInternal_semanticEvidenceLookupTimeout_recordsGapOnly() throws Exception {
        setAuthenticated();
        hcadProperties.getSemanticEvidence().setLookupTimeoutMs(5);
        HcadSemanticEvidenceCache semanticEvidenceCache = mock(HcadSemanticEvidenceCache.class);
        HcadSemanticEvidenceWarmupService warmupService = mock(HcadSemanticEvidenceWarmupService.class);
        hcadFilter = new HCADFilter(
                trustedProjectionFactory,
                preProtectablePromotionScorer,
                hcadProperties,
                () -> pendingAnomalyTriggerOrchestrator,
                () -> hcadEvaluationWriter,
                new InMemoryHcadObservationWindowRepository(),
                () -> semanticEvidenceCache,
                () -> warmupService);
        TrustedHcadContextProjection projection = projection();
        HcadPreProtectablePromotionAssessment assessment = new HcadPreProtectablePromotionAssessment(
                10,
                HcadPreProtectablePromotionBand.LOW,
                false,
                List.of(),
                List.of(),
                List.of(),
                "lookup timeout stays gap-only",
                "hcad-promotion-v2-trusted-projection",
                Map.of("earlyAnalysisScore", 10));
        when(trustedProjectionFactory.project(any(), any())).thenReturn(projection);
        when(semanticEvidenceCache.provider()).thenReturn(
                HcadProperties.SemanticEvidenceSettings.EvidenceCacheProvider.REDIS);
        when(semanticEvidenceCache.get(any())).thenAnswer(invocation -> {
            Thread.sleep(50);
            return Optional.empty();
        });
        when(preProtectablePromotionScorer.score(eq(projection), any(CachedSemanticEvidenceProjection.class)))
                .thenReturn(assessment);

        hcadFilter.doFilterInternal(request, response, filterChain);

        ArgumentCaptor<CachedSemanticEvidenceProjection> evidenceCaptor =
                ArgumentCaptor.forClass(CachedSemanticEvidenceProjection.class);
        verify(preProtectablePromotionScorer).score(eq(projection), evidenceCaptor.capture());
        assertThat(evidenceCaptor.getValue().evidenceGapCodes())
                .contains("SEMANTIC_EVIDENCE_LOOKUP_TIMEOUT");
        verify(warmupService, never())
                .requestWarmup(any(HcadSemanticEvidenceWarmupRequest.class), eq(semanticEvidenceCache));
    }

    @Test
    @DisplayName("semantic evidence mismatch should be recorded and should request current-key warmup")
    void doFilterInternal_semanticEvidenceMismatch_requestsWarmup() throws Exception {
        setAuthenticated();
        HcadSemanticEvidenceCache semanticEvidenceCache = mock(HcadSemanticEvidenceCache.class);
        HcadSemanticEvidenceWarmupService warmupService = mock(HcadSemanticEvidenceWarmupService.class);
        hcadFilter = new HCADFilter(
                trustedProjectionFactory,
                preProtectablePromotionScorer,
                hcadProperties,
                () -> pendingAnomalyTriggerOrchestrator,
                () -> hcadEvaluationWriter,
                new InMemoryHcadObservationWindowRepository(),
                () -> semanticEvidenceCache,
                () -> warmupService);
        TrustedHcadContextProjection projection = projection();
        HcadPreProtectablePromotionAssessment assessment = new HcadPreProtectablePromotionAssessment(
                10,
                HcadPreProtectablePromotionBand.LOW,
                false,
                List.of(),
                List.of(),
                List.of(),
                "mismatch stays gap-only",
                "hcad-promotion-v2-trusted-projection",
                Map.of("earlyAnalysisScore", 10));
        when(trustedProjectionFactory.project(any(), any())).thenReturn(projection);
        when(semanticEvidenceCache.get(any()))
                .thenReturn(Optional.of(semanticEntry()
                        .withStatus(HcadSemanticEvidenceCacheStatus.VERSION_MISMATCH, "VERSION_MISMATCH")));
        when(warmupService.requestWarmup(any(HcadSemanticEvidenceWarmupRequest.class), eq(semanticEvidenceCache)))
                .thenReturn(HcadSemanticEvidenceWarmupResult.queued());
        when(preProtectablePromotionScorer.score(eq(projection), any(CachedSemanticEvidenceProjection.class)))
                .thenReturn(assessment);

        hcadFilter.doFilterInternal(request, response, filterChain);

        ArgumentCaptor<CachedSemanticEvidenceProjection> evidenceCaptor =
                ArgumentCaptor.forClass(CachedSemanticEvidenceProjection.class);
        verify(preProtectablePromotionScorer).score(eq(projection), evidenceCaptor.capture());
        assertThat(evidenceCaptor.getValue().hasUsableEvidence()).isFalse();
        assertThat(evidenceCaptor.getValue().evidenceGapCodes())
                .contains("VERSION_MISMATCH", "WARMUP_QUEUED");
        verify(warmupService, times(3))
                .requestWarmup(any(HcadSemanticEvidenceWarmupRequest.class), eq(semanticEvidenceCache));
    }

    @Test
    @DisplayName("semantic source absent negative cache hit should be recorded on the evaluation")
    void doFilterInternal_semanticNegativeCacheHit_marksEvaluationNegativeCacheHit() throws Exception {
        setAuthenticated();
        HcadSemanticEvidenceCache semanticEvidenceCache = mock(HcadSemanticEvidenceCache.class);
        hcadFilter = new HCADFilter(
                trustedProjectionFactory,
                preProtectablePromotionScorer,
                hcadProperties,
                () -> null,
                () -> hcadEvaluationWriter,
                new InMemoryHcadObservationWindowRepository(),
                () -> semanticEvidenceCache,
                () -> null);
        TrustedHcadContextProjection projection = projection();
        HcadPreProtectablePromotionAssessment assessment = new HcadPreProtectablePromotionAssessment(
                10,
                HcadPreProtectablePromotionBand.LOW,
                false,
                List.of(),
                List.of(),
                List.of(),
                "source absent stays gap-only",
                "hcad-promotion-v2-trusted-projection",
                Map.of("earlyAnalysisScore", 10));
        when(trustedProjectionFactory.project(any(), any())).thenReturn(projection);
        when(semanticEvidenceCache.get(any())).thenReturn(Optional.of(sourceAbsentEntry()));
        when(preProtectablePromotionScorer.score(eq(projection), any(CachedSemanticEvidenceProjection.class)))
                .thenReturn(assessment);

        hcadFilter.doFilterInternal(request, response, filterChain);

        ArgumentCaptor<CachedSemanticEvidenceProjection> evidenceCaptor =
                ArgumentCaptor.forClass(CachedSemanticEvidenceProjection.class);
        verify(preProtectablePromotionScorer).score(eq(projection), evidenceCaptor.capture());
        assertThat(evidenceCaptor.getValue().evidenceGapCodes()).contains("SOURCE_ABSENT");
        assertThat(request.getAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_NEGATIVE_CACHE_HIT))
                .isEqualTo(true);
        verify(hcadEvaluationWriter, never()).recordCandidate(any(), any());
        verify(hcadEvaluationWriter, never()).markNegativeCacheHit(any());
    }

    @Test
    @DisplayName("observation-only request should update existing window evaluation summary without deep evaluation")
    void doFilterInternal_observationOnlyRequest_updatesWindowEvaluationSummary() throws Exception {
        setAuthenticated();
        hcadFilter = new HCADFilter(
                trustedProjectionFactory,
                preProtectablePromotionScorer,
                hcadProperties,
                () -> null,
                () -> hcadEvaluationWriter);
        TrustedHcadContextProjection projection = projection();
        HcadPreProtectablePromotionAssessment assessment = new HcadPreProtectablePromotionAssessment(
                75,
                HcadPreProtectablePromotionBand.REDLINE,
                true,
                List.of("IMPOSSIBLE_TRAVEL"),
                List.of("REQUEST_BURST", "RAPID_SEQUENCE", "PREVIOUS_PATH_JUMP"),
                List.of("IMPOSSIBLE_TRAVEL", "REQUEST_BURST", "RAPID_SEQUENCE", "PREVIOUS_PATH_JUMP"),
                "trusted redline projection",
                "hcad-promotion-v2-trusted-projection",
                Map.of("earlyAnalysisScore", 75));
        when(trustedProjectionFactory.project(any(), any())).thenReturn(projection);
        when(preProtectablePromotionScorer.score(projection)).thenReturn(assessment);
        when(hcadEvaluationWriter.recordCandidate(eq(HcadPreTriggerMode.SHADOW), any())).thenReturn("eval-low");

        MockHttpServletRequest first = hcadRequest("GET", "/api/dashboard", "session-1", "203.0.113.10", "JUnit");
        MockHttpServletRequest second = hcadRequest("GET", "/api/menus", "session-1", "203.0.113.10", "JUnit");

        hcadFilter.doFilterInternal(first, response, new MockFilterChain());
        hcadFilter.doFilterInternal(second, new MockHttpServletResponse(), new MockFilterChain());

        ArgumentCaptor<HcadObservationWindowLease> leaseCaptor =
                ArgumentCaptor.forClass(HcadObservationWindowLease.class);
        verify(hcadEvaluationWriter).recordCandidate(eq(HcadPreTriggerMode.SHADOW), any());
        verify(hcadEvaluationWriter).updateWindowObservation(
                eq(first.getAttribute("hcad.actorSessionKey").toString()),
                eq(first.getAttribute("hcad.windowId").toString()),
                leaseCaptor.capture());
        assertThat(leaseCaptor.getValue().requestCount()).isEqualTo(2);
        assertThat(leaseCaptor.getValue().samplePaths()).containsExactly("/api/dashboard", "/api/menus");
        verify(trustedProjectionFactory, times(1)).project(any(), any());
        verify(preProtectablePromotionScorer, times(1)).score(any());
    }

    @Test
    @DisplayName("parallel fan-out in same actor session should perform one deep HCAD evaluation and one trigger attempt")
    void doFilterInternal_sameActorSessionTenParallelPaths_coalescesDeepEvaluationAndTrigger() throws Exception {
        setAuthenticated();
        TrustedHcadContextProjection projection = projection();
        HcadPreProtectablePromotionAssessment assessment = new HcadPreProtectablePromotionAssessment(
                75,
                HcadPreProtectablePromotionBand.REDLINE,
                true,
                List.of("IMPOSSIBLE_TRAVEL"),
                List.of("REQUEST_BURST"),
                List.of("IMPOSSIBLE_TRAVEL", "REQUEST_BURST"),
                "trusted projection",
                "hcad-promotion-v2-trusted-projection",
                Map.of("earlyAnalysisScore", 75));

        when(trustedProjectionFactory.project(any(), any())).thenReturn(projection);
        when(preProtectablePromotionScorer.score(projection)).thenReturn(assessment);

        int requestCount = 10;
        CountDownLatch ready = new CountDownLatch(requestCount);
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(requestCount);
        List<Future<MockHttpServletRequest>> futures = new ArrayList<>();
        for (int i = 0; i < requestCount; i++) {
            int index = i;
            futures.add(executor.submit(() -> {
                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken("testUser", "password", Collections.emptyList());
                SecurityContextHolder.getContext().setAuthentication(auth);
                MockHttpServletRequest fanOutRequest = hcadRequest("GET", "/api/fanout/" + index,
                        "session-1", "203.0.113.10", "JUnit");
                fanOutRequest.setQueryString("refresh=" + index);
                ready.countDown();
                start.await(2, TimeUnit.SECONDS);
                hcadFilter.doFilterInternal(fanOutRequest, new MockHttpServletResponse(), new MockFilterChain());
                SecurityContextHolder.clearContext();
                return fanOutRequest;
            }));
        }
        assertThat(ready.await(2, TimeUnit.SECONDS)).isTrue();
        start.countDown();
        List<MockHttpServletRequest> completed = new ArrayList<>();
        for (Future<MockHttpServletRequest> future : futures) {
            completed.add(future.get(5, TimeUnit.SECONDS));
        }
        executor.shutdownNow();

        verify(trustedProjectionFactory, times(1)).project(any(), any());
        verify(preProtectablePromotionScorer, times(1)).score(any());
        verify(pendingAnomalyTriggerOrchestrator, times(1)).maybeTrigger(any(), any());
        assertThat(completed)
                .extracting(request -> request.getAttribute("hcad.actorSessionKey"))
                .containsOnly(completed.get(0).getAttribute("hcad.actorSessionKey"));
        assertThat(completed)
                .extracting(request -> request.getAttribute("hcad.windowId"))
                .containsOnly(completed.get(0).getAttribute("hcad.windowId"));
        List<Integer> observedCounts = completed.stream()
                .map(request -> (Integer) request.getAttribute("hcad.windowRequestCount"))
                .toList();
        assertThat(observedCounts).allMatch(count -> count >= 1 && count <= requestCount);
        assertThat(observedCounts).contains(requestCount);
    }

    @Test
    @DisplayName("same resource refresh with query and path parameter changes should stay in one HCAD window")
    void doFilterInternal_sameActorSessionQueryAndPathParameterChanges_coalescesWithinWindow() throws Exception {
        setAuthenticated();
        TrustedHcadContextProjection projection = projection();
        HcadPreProtectablePromotionAssessment assessment = new HcadPreProtectablePromotionAssessment(
                75,
                HcadPreProtectablePromotionBand.REDLINE,
                true,
                List.of("IMPOSSIBLE_TRAVEL"),
                List.of("REQUEST_BURST"),
                List.of("IMPOSSIBLE_TRAVEL", "REQUEST_BURST"),
                "trusted projection",
                "hcad-promotion-v2-trusted-projection",
                Map.of("earlyAnalysisScore", 75));

        when(trustedProjectionFactory.project(any(), any())).thenReturn(projection);
        when(preProtectablePromotionScorer.score(projection)).thenReturn(assessment);

        MockHttpServletRequest first = hcadRequest("GET", "/api/orders/1001", "session-1", "203.0.113.10", "JUnit");
        first.setQueryString("refresh=1");
        MockHttpServletRequest second = hcadRequest("GET", "/api/orders/1002", "session-1", "203.0.113.10", "JUnit");
        second.setQueryString("refresh=2");

        hcadFilter.doFilterInternal(first, response, new MockFilterChain());
        hcadFilter.doFilterInternal(second, new MockHttpServletResponse(), new MockFilterChain());

        verify(trustedProjectionFactory, times(1)).project(any(), any());
        verify(preProtectablePromotionScorer, times(1)).score(any());
        verify(pendingAnomalyTriggerOrchestrator, times(1)).maybeTrigger(any(), any());
        assertThat(second.getAttribute("hcad.windowId")).isEqualTo(first.getAttribute("hcad.windowId"));
        assertThat(second.getAttribute("hcad.windowRequestCount")).isEqualTo(2);
    }

    @Test
    @DisplayName("actor-session evaluation TTL should suppress deep re-evaluation after coalesce window expires")
    void doFilterInternal_sameActorSessionWithinEvaluationTtl_suppressesRepeatedDeepEvaluation() throws Exception {
        setAuthenticated();
        hcadProperties.getPreTrigger().setCoalesceWindowMs(1);
        hcadProperties.getPreTrigger().setActorSessionEvaluationTtlSeconds(2);
        TrustedHcadContextProjection projection = projection();
        HcadPreProtectablePromotionAssessment assessment = new HcadPreProtectablePromotionAssessment(
                75,
                HcadPreProtectablePromotionBand.REDLINE,
                true,
                List.of("IMPOSSIBLE_TRAVEL"),
                List.of("REQUEST_BURST"),
                List.of("IMPOSSIBLE_TRAVEL", "REQUEST_BURST"),
                "trusted projection",
                "hcad-promotion-v2-trusted-projection",
                Map.of("earlyAnalysisScore", 75));

        when(trustedProjectionFactory.project(any(), any())).thenReturn(projection);
        when(preProtectablePromotionScorer.score(projection)).thenReturn(assessment);

        MockHttpServletRequest first = hcadRequest("GET", "/api/orders/1001", "session-1", "203.0.113.10", "JUnit");
        MockHttpServletRequest second = hcadRequest("GET", "/api/orders/1002", "session-1", "203.0.113.10", "JUnit");
        second.setQueryString("refresh=2");

        hcadFilter.doFilterInternal(first, response, new MockFilterChain());
        Thread.sleep(25);
        hcadFilter.doFilterInternal(second, new MockHttpServletResponse(), new MockFilterChain());

        verify(trustedProjectionFactory, times(1)).project(any(), any());
        verify(preProtectablePromotionScorer, times(1)).score(any());
        verify(pendingAnomalyTriggerOrchestrator, times(1)).maybeTrigger(any(), any());
        assertThat(second.getAttribute("hcad.windowId")).isNotEqualTo(first.getAttribute("hcad.windowId"));
        assertThat(second.getAttribute("hcad.windowRequestCount")).isEqualTo(1);
        assertThat(second.getAttribute("hcad.actorSessionEvaluationSuppressed")).isEqualTo(true);
    }

    @Test
    @DisplayName("new trusted anchor signal should allow one extra deep evaluation in same window")
    void doFilterInternal_newTrustedAnchorSignal_allowsEscalationEvaluation() throws Exception {
        setAuthenticated();
        hcadProperties.getPreTrigger().setEvaluationTtlSeconds(60);
        TrustedHcadContextProjection projection = projection();
        HcadPreProtectablePromotionAssessment assessment = new HcadPreProtectablePromotionAssessment(
                75,
                HcadPreProtectablePromotionBand.REDLINE,
                true,
                List.of("IMPOSSIBLE_TRAVEL"),
                List.of("REQUEST_BURST"),
                List.of("IMPOSSIBLE_TRAVEL", "REQUEST_BURST"),
                "trusted projection",
                "hcad-promotion-v2-trusted-projection",
                Map.of("earlyAnalysisScore", 75));

        when(trustedProjectionFactory.project(any(), any())).thenReturn(projection);
        when(preProtectablePromotionScorer.score(projection)).thenReturn(assessment);
        when(trustedProjectionFactory.probeAnchorSignals(any(), any())).thenReturn(
                null,
                new HcadTrustedAnchorSignalProbe(
                        List.of("FAILED_LOGIN_BURST"),
                        "FAILED_LOGIN_BURST"));

        MockHttpServletRequest first = hcadRequest("GET", "/api/orders/1001", "session-1", "203.0.113.10", "JUnit");
        MockHttpServletRequest second = hcadRequest("GET", "/api/orders/1002", "session-1", "203.0.113.10", "JUnit");

        hcadFilter.doFilterInternal(first, response, new MockFilterChain());
        hcadFilter.doFilterInternal(second, new MockHttpServletResponse(), new MockFilterChain());

        verify(trustedProjectionFactory, times(2)).project(any(), any());
        verify(preProtectablePromotionScorer, times(2)).score(any());
        verify(pendingAnomalyTriggerOrchestrator, times(2)).maybeTrigger(any(), any());
        assertThat(second.getAttribute("hcad.windowId")).isEqualTo(first.getAttribute("hcad.windowId"));
        assertThat(second.getAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_ESCALATION_EVALUATION))
                .isEqualTo(true);
        assertThat(second.getAttribute("hcad.reEvaluationSignals").toString())
                .contains("FAILED_LOGIN_BURST");
    }

    @Test
    @DisplayName("different user, session, IP, and user-agent should acquire separate HCAD windows")
    void doFilterInternal_differentActorContexts_shouldEvaluateIndependently() throws Exception {
        TrustedHcadContextProjection projection = projection();
        HcadPreProtectablePromotionAssessment assessment = new HcadPreProtectablePromotionAssessment(
                75,
                HcadPreProtectablePromotionBand.REDLINE,
                true,
                List.of("IMPOSSIBLE_TRAVEL"),
                List.of("REQUEST_BURST"),
                List.of("IMPOSSIBLE_TRAVEL", "REQUEST_BURST"),
                "trusted projection",
                "hcad-promotion-v2-trusted-projection",
                Map.of("earlyAnalysisScore", 75));

        when(trustedProjectionFactory.project(any(), any())).thenReturn(projection);
        when(preProtectablePromotionScorer.score(projection)).thenReturn(assessment);

        runFilterAs("testUser", hcadRequest("GET", "/api/dashboard", "session-1", "203.0.113.10", "JUnit"));
        runFilterAs("testUser", hcadRequest("GET", "/api/dashboard", "session-2", "203.0.113.10", "JUnit"));
        runFilterAs("testUser", hcadRequest("GET", "/api/dashboard", "session-1", "203.0.113.11", "JUnit"));
        runFilterAs("testUser", hcadRequest("GET", "/api/dashboard", "session-1", "203.0.113.10", "Different"));
        runFilterAs("otherUser", hcadRequest("GET", "/api/dashboard", "session-1", "203.0.113.10", "JUnit"));

        verify(trustedProjectionFactory, times(5)).project(any(), any());
        verify(preProtectablePromotionScorer, times(5)).score(any());
        verify(pendingAnomalyTriggerOrchestrator, times(5)).maybeTrigger(any(), any());
    }

    @Test
    @DisplayName("shouldNotFilter does not trust browser fetch destinations to bypass HCAD")
    void shouldNotFilter_nonInteractiveFetchDestinations_returnsFalse() {
        request.setRequestURI("/tenant-assets/logo");
        request.addHeader("Sec-Fetch-Dest", "image");
        assertThat(hcadFilter.shouldNotFilter(request)).isFalse();

        request = new MockHttpServletRequest();
        request.setRequestURI("/bundle/runtime");
        request.addHeader("Sec-Fetch-Dest", "script");
        assertThat(hcadFilter.shouldNotFilter(request)).isFalse();

        request = new MockHttpServletRequest();
        request.setRequestURI("/theme/main");
        request.addHeader("Sec-Fetch-Dest", "style");
        assertThat(hcadFilter.shouldNotFilter(request)).isFalse();

        request = new MockHttpServletRequest();
        request.setRequestURI("/font/primary");
        request.addHeader("Sec-Fetch-Dest", "font");
        assertThat(hcadFilter.shouldNotFilter(request)).isFalse();
    }

    @Test
    @DisplayName("shouldNotFilter uses configured excluded patterns for infrastructure paths")
    void shouldNotFilter_configuredInfrastructurePatterns_returnsTrue() {
        hcadProperties.getFilter().getExcludedPatterns().add("/health");
        hcadProperties.getFilter().getExcludedPatterns().add("/actuator/**");

        request.setRequestURI("/health");
        assertThat(hcadFilter.shouldNotFilter(request)).isTrue();

        request.setRequestURI("/actuator/health");
        assertThat(hcadFilter.shouldNotFilter(request)).isTrue();

        request.setRequestURI("/actuator/info");
        assertThat(hcadFilter.shouldNotFilter(request)).isTrue();
    }

    @Test
    @DisplayName("shouldNotFilter excludes infrastructure paths behind a servlet context path")
    void shouldNotFilter_contextPathInfraPath_returnsTrue() {
        hcadProperties.getFilter().getExcludedPatterns().add("/actuator/**");
        request.setContextPath("/contexa");
        request.setServletPath("/actuator/health");
        request.setRequestURI("/contexa/actuator/health");

        assertThat(hcadFilter.shouldNotFilter(request)).isTrue();
    }

    @Test
    @DisplayName("shouldNotFilter excludes AI monitor paths by default to prevent self-observation")
    void shouldNotFilter_defaultAiMonitorPatterns_returnsTrue() {
        request.setRequestURI("/contexa/admin/ai-monitor/hcad");
        assertThat(hcadFilter.shouldNotFilter(request)).isTrue();

        request = new MockHttpServletRequest();
        request.setRequestURI("/contexa/admin/api/ai-monitor/hcad");
        assertThat(hcadFilter.shouldNotFilter(request)).isTrue();

        request = new MockHttpServletRequest();
        request.setRequestURI("/contexa/admin/security-monitor/hcad");
        assertThat(hcadFilter.shouldNotFilter(request)).isTrue();

        request = new MockHttpServletRequest();
        request.setRequestURI("/contexa/admin/api/security-monitor/hcad/summary");
        assertThat(hcadFilter.shouldNotFilter(request)).isTrue();
    }

    @Test
    @DisplayName("shouldNotFilter returns false for API paths")
    void shouldNotFilter_apiPaths_returnsFalse() {
        request.setRequestURI("/api/users");
        request.addHeader("Sec-Fetch-Dest", "empty");
        assertThat(hcadFilter.shouldNotFilter(request)).isFalse();
    }

    @Test
    @DisplayName("shouldNotFilter excludes non-actionable static resources and browser probe paths")
    void shouldNotFilter_nonActionableMonitoringPaths_returnsTrue() {
        request.setRequestURI("/img/logo.png");
        assertThat(hcadFilter.shouldNotFilter(request)).isTrue();

        request = new MockHttpServletRequest();
        request.setRequestURI("/.well-known/appspecific/com.chrome.devtools.json");
        assertThat(hcadFilter.shouldNotFilter(request)).isTrue();

        request = new MockHttpServletRequest();
        request.setRequestURI("/favicon.ico");
        assertThat(hcadFilter.shouldNotFilter(request)).isTrue();

        request = new MockHttpServletRequest();
        request.setRequestURI("/api/report.json");
        assertThat(hcadFilter.shouldNotFilter(request)).isFalse();

        request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");
        assertThat(hcadFilter.shouldNotFilter(request)).isFalse();
    }

    @Test
    @DisplayName("authenticated login entry points should bypass HCAD evaluation")
    void doFilter_authenticatedLoginEntryPoints_bypassEvaluation() throws Exception {
        setAuthenticated();

        request.setRequestURI("/contexa/admin/login");
        hcadFilter.doFilter(request, response, filterChain);

        assertThat(filterChain.getRequest()).isNotNull();
        verify(trustedProjectionFactory, never()).project(any(), any());
        verify(preProtectablePromotionScorer, never()).score(any());
        verify(pendingAnomalyTriggerOrchestrator, never()).maybeTrigger(any(), any());

        request = new MockHttpServletRequest("GET", "/mfa/login");
        assertThat(hcadFilter.shouldNotFilter(request)).isTrue();
    }

    @Test
    @DisplayName("Unauthenticated request passes through without analysis")
    void doFilterInternal_unauthenticated_passesThrough() throws Exception {
        hcadFilter.doFilterInternal(request, response, filterChain);

        assertThat(filterChain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("Exception during trusted projection results in graceful passthrough")
    void doFilterInternal_exceptionDuringAnalysis_gracefulPassthrough() throws Exception {
        setAuthenticated();
        when(trustedProjectionFactory.project(any(), any()))
                .thenThrow(new RuntimeException("Analysis failed"));

        hcadFilter.doFilterInternal(request, response, filterChain);

        assertThat(filterChain.getRequest()).isNotNull();
        assertThat(request.getAttribute("hcad.analysisStatus")).isEqualTo("FAILED");
        assertThat(request.getAttribute("hcad.failReason")).isEqualTo("RuntimeException");
    }

    @Test
    @DisplayName("Disabled HCAD passes through without analysis")
    void doFilterInternal_disabled_passesThrough() throws Exception {
        hcadProperties.setEnabled(false);
        setAuthenticated();

        hcadFilter.doFilterInternal(request, response, filterChain);

        assertThat(filterChain.getRequest()).isNotNull();
    }

    private TrustedHcadContextProjection projection() {
        return new TrustedHcadContextProjection(
                "testUser",
                "tenant-1",
                "org-1",
                "session-1",
                "ctx-1",
                "GET",
                "/api/test",
                "127.0.0.1",
                "mfa",
                "high",
                true,
                10L,
                "policy-1",
                false,
                false,
                List.of(),
                4,
                12,
                true,
                "/api/previous",
                false,
                0.9,
                true,
                HcadBaselineComparison.unavailable(20),
                HcadPromptSecurityContextFieldRegistry.version(),
                HcadPromptSecurityContextFieldRegistry.snapshot(Map.of()),
                Map.of(),
                Map.of());
    }

    private void setAuthenticated() {
        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken("testUser", "password", Collections.emptyList());
        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    private void runFilterAs(String username, MockHttpServletRequest request) throws Exception {
        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(username, "password", Collections.emptyList());
        SecurityContextHolder.getContext().setAuthentication(auth);
        hcadFilter.doFilterInternal(request, new MockHttpServletResponse(), new MockFilterChain());
        SecurityContextHolder.clearContext();
    }

    private MockHttpServletRequest hcadRequest(
            String method,
            String path,
            String sessionId,
            String remoteAddr,
            String userAgent) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        request.setRequestURI(path);
        request.setServletPath(path);
        request.setRequestedSessionId(sessionId);
        request.setRemoteAddr(remoteAddr);
        request.addHeader("User-Agent", userAgent);
        return request;
    }

    private HcadSemanticEvidenceEntry semanticEntry() {
        return new HcadSemanticEvidenceEntry(
                HcadSemanticEvidenceKey.riskRequestSimilarity(
                        "tenant-1",
                        "testUser",
                        "/api/test",
                        "policy-1",
                        HcadPromptSecurityContextFieldRegistry.version(),
                        hcadProperties.getSemanticEvidence().getEmbeddingModel(),
                        hcadProperties.getVector().getEmbeddingDimension(),
                        hcadProperties.getSemanticEvidence().getEvidenceVersion()),
                HcadSemanticEvidenceCacheStatus.HIT,
                "source-v1",
                hcadProperties.getSemanticEvidence().getEvidenceVersion(),
                hcadProperties.getSemanticEvidence().getEmbeddingModel(),
                hcadProperties.getVector().getEmbeddingDimension(),
                0.2d,
                0.91d,
                0.7d,
                "{}",
                List.of(),
                Instant.now(),
                Instant.now().plusSeconds(300));
    }

    private HcadSemanticEvidenceEntry sourceAbsentEntry() {
        return new HcadSemanticEvidenceEntry(
                HcadSemanticEvidenceKey.riskRequestSimilarity(
                        "tenant-1",
                        "testUser",
                        "/api/test",
                        "policy-1",
                        HcadPromptSecurityContextFieldRegistry.version(),
                        hcadProperties.getSemanticEvidence().getEmbeddingModel(),
                        hcadProperties.getVector().getEmbeddingDimension(),
                        hcadProperties.getSemanticEvidence().getEvidenceVersion()),
                HcadSemanticEvidenceCacheStatus.NEGATIVE_CACHE_HIT,
                null,
                hcadProperties.getSemanticEvidence().getEvidenceVersion(),
                hcadProperties.getSemanticEvidence().getEmbeddingModel(),
                hcadProperties.getVector().getEmbeddingDimension(),
                null,
                null,
                null,
                null,
                List.of("SOURCE_ABSENT"),
                Instant.now(),
                Instant.now().plusSeconds(300));
    }
}
