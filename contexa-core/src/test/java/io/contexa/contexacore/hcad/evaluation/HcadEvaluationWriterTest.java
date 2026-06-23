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
package io.contexa.contexacore.hcad.evaluation;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.domain.entity.HcadDetectionEvaluation;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionAttributes;
import io.contexa.contexacore.hcad.trigger.HcadPreTriggerMode;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyEvidenceReport;
import io.contexa.contexacore.hcad.trigger.window.HcadObservationWindowLease;
import io.contexa.contexacore.repository.HcadDetectionEvaluationRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcOperations;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class HcadEvaluationWriterTest {

    @Test
    @DisplayName("recordCandidate should persist HCAD evaluation row fields")
    void recordCandidate_shouldPersistEvaluationFields() {
        HcadDetectionEvaluationRepository repository = mock(HcadDetectionEvaluationRepository.class);
        when(repository.save(any(HcadDetectionEvaluation.class))).thenAnswer(invocation -> invocation.getArgument(0));
        HcadEvaluationWriter writer = new HcadEvaluationWriter(repository, new ObjectMapper());

        String evaluationId = writer.recordCandidate(HcadPreTriggerMode.SHADOW, report());

        ArgumentCaptor<HcadDetectionEvaluation> captor = ArgumentCaptor.forClass(HcadDetectionEvaluation.class);
        verify(repository).save(captor.capture());
        HcadDetectionEvaluation saved = captor.getValue();
        assertThat(evaluationId).isNotBlank();
        assertThat(saved.getEvaluationId()).isEqualTo(evaluationId);
        assertThat(saved.getMode()).isEqualTo("SHADOW");
        assertThat(saved.getUserId()).isEqualTo("alice");
        assertThat(saved.getActorSessionKey()).isEqualTo("actor-1");
        assertThat(saved.getWindowId()).isEqualTo("window-1");
        assertThat(saved.getTriggerScope()).isEqualTo("SESSION_WINDOW");
        assertThat(saved.getRequestCount()).isEqualTo(3);
        assertThat(saved.getDuplicateSuppressedCount()).isEqualTo(2);
        assertThat(saved.getSamplePaths()).contains("/admin/reports");
        assertThat(saved.getHttpMethod()).isEqualTo("GET");
        assertThat(saved.getRequestPath()).isEqualTo("/admin/reports");
        assertThat(saved.getEarlyAnalysisScore()).isEqualTo(72);
        assertThat(saved.getBand()).isEqualTo("REDLINE");
        assertThat(saved.getTriggeredLlm()).isFalse();
        assertThat(saved.getOutcomeClass()).isEqualTo("UNKNOWN");
        assertThat(saved.getAnchorSignals()).contains("FAILED_LOGIN_BURST");
        assertThat(saved.getTestRunId()).isEqualTo("run-evidence-1");
        assertThat(saved.getNonTriggerReason()).isNull();
        assertThat(saved.getEvidenceGapCodes()).contains("PERSONAL_BASELINE_UNAVAILABLE");
        assertThat(saved.getBaselineAvailable()).isFalse();
        assertThat(saved.getBaselineEstablished()).isFalse();
        assertThat(saved.getBaselineUpdateCount()).isZero();
        assertThat(saved.getBaselineMinSamples()).isZero();
        assertThat(saved.getBaselineComparedDimensions()).isZero();
        assertThat(saved.getTriggerDecisionReason()).isEqualTo("TRIGGER_CANDIDATE");
        assertThat(saved.getSignalSnapshotJson()).contains("signalProvenance");
    }

    @Test
    @DisplayName("recordCandidate JDBC insert should include queryable baseline evidence columns")
    void recordCandidate_jdbcInsert_shouldIncludeBaselineEvidenceColumns() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        HcadEvaluationWriter writer = new HcadEvaluationWriter(jdbcOperations, new ObjectMapper());

        writer.recordCandidate(HcadPreTriggerMode.SHADOW, report());

        ArgumentCaptor<Object[]> argsCaptor = ArgumentCaptor.forClass(Object[].class);
        verify(jdbcOperations).update(any(String.class), argsCaptor.capture());
        Object[] args = argsCaptor.getValue();
        assertThat(args).hasSize(58);
        assertThat(args[4]).isEqualTo("run-evidence-1");
        assertThat(args[30]).isEqualTo(false);
        assertThat(args[31]).isEqualTo(false);
        assertThat(args[32]).isEqualTo(0L);
        assertThat(args[33]).isEqualTo(0);
        assertThat(args[34]).isEqualTo(0);
        assertThat(args[35]).isEqualTo(0);
        assertThat(args[36]).isEqualTo(0.0d);
        assertThat(args[38]).isEqualTo("{}");
        assertThat(args[39]).isEqualTo("{}");
    }

    @Test
    @DisplayName("recordCandidate should persist non trigger reason and evidence gaps")
    void recordCandidate_shouldPersistNonTriggerReasonAndEvidenceGaps() {
        HcadDetectionEvaluationRepository repository = mock(HcadDetectionEvaluationRepository.class);
        when(repository.save(any(HcadDetectionEvaluation.class))).thenAnswer(invocation -> invocation.getArgument(0));
        HcadEvaluationWriter writer = new HcadEvaluationWriter(repository, new ObjectMapper());

        writer.recordCandidate(HcadPreTriggerMode.SHADOW, PendingAnomalyEvidenceReport.noTrigger(
                "alice",
                "ctx-1",
                "base-1",
                "request-2",
                "session-1",
                "/admin/dashboard",
                "GET",
                "203.0.113.10",
                10,
                "LOW",
                false,
                "hcad-promotion-v2-trusted-projection",
                List.of(),
                List.of("PREVIOUS_PATH_JUMP"),
                List.of("PREVIOUS_PATH_JUMP"),
                "supporting signal only",
                Map.of(
                        "actorSessionKey", "actor-1",
                        "windowId", "window-1")));

        ArgumentCaptor<HcadDetectionEvaluation> captor = ArgumentCaptor.forClass(HcadDetectionEvaluation.class);
        verify(repository).save(captor.capture());
        HcadDetectionEvaluation saved = captor.getValue();
        assertThat(saved.getTriggeredLlm()).isFalse();
        assertThat(saved.getNonTriggerReason()).isEqualTo("SUPPORTING_SIGNAL_ONLY");
        assertThat(saved.getEvidenceGapCodes())
                .contains("PERSONAL_BASELINE_UNAVAILABLE", "TRUSTED_ANCHOR_ABSENT");
        assertThat(saved.getTriggerDecisionReason()).isEqualTo("SUPPORTING_SIGNAL_ONLY");
    }

    @Test
    @DisplayName("markTriggered should update triggered flag and timestamp")
    void markTriggered_shouldUpdateEvaluation() {
        HcadDetectionEvaluationRepository repository = mock(HcadDetectionEvaluationRepository.class);
        HcadDetectionEvaluation evaluation = HcadDetectionEvaluation.builder()
                .evaluationId("eval-1")
                .mode("SHADOW")
                .triggeredLlm(false)
                .duplicateSuppressed(false)
                .outcomeClass("UNKNOWN")
                .build();
        when(repository.findById("eval-1")).thenReturn(Optional.of(evaluation));
        HcadEvaluationWriter writer = new HcadEvaluationWriter(repository, new ObjectMapper());

        writer.markTriggered("eval-1");

        assertThat(evaluation.getTriggeredLlm()).isTrue();
        assertThat(evaluation.getNonTriggerReason()).isNull();
        assertThat(evaluation.getTriggerDecisionReason()).isEqualTo("TRIGGER_PUBLISHED");
        assertThat(evaluation.getTriggeredAt()).isNotNull();
        verify(repository).save(evaluation);
    }

    @Test
    @DisplayName("updateWindowObservation should refresh request count and sampled paths")
    void updateWindowObservation_shouldRefreshWindowSummary() {
        HcadDetectionEvaluationRepository repository = mock(HcadDetectionEvaluationRepository.class);
        HcadDetectionEvaluation evaluation = HcadDetectionEvaluation.builder()
                .evaluationId("eval-window")
                .actorSessionKey("actor-1")
                .windowId("window-1")
                .requestCount(1)
                .duplicateSuppressedCount(0)
                .mode("SHADOW")
                .outcomeClass("UNKNOWN")
                .build();
        when(repository.findByActorSessionKeyAndWindowId("actor-1", "window-1"))
                .thenReturn(List.of(evaluation));
        HcadEvaluationWriter writer = new HcadEvaluationWriter(repository, new ObjectMapper());

        writer.updateWindowObservation(
                "actor-1",
                "window-1",
                new HcadObservationWindowLease(
                        false,
                        "actor-1",
                        "window-1",
                        10,
                        List.of("/api/fanout/{id}"),
                        List.of("/api/fanout/1", "/api/fanout/2")));

        assertThat(evaluation.getRequestCount()).isEqualTo(10);
        assertThat(evaluation.getDuplicateSuppressedCount()).isEqualTo(9);
        assertThat(evaluation.getResourceFamilies()).contains("/api/fanout/{id}");
        assertThat(evaluation.getSamplePaths()).contains("/api/fanout/1", "/api/fanout/2");
        verify(repository).save(evaluation);
    }

    @Test
    @DisplayName("markDecided should update LLM outcome fields")
    void markDecided_shouldUpdateLlmOutcomeFields() {
        HcadDetectionEvaluationRepository repository = mock(HcadDetectionEvaluationRepository.class);
        HcadDetectionEvaluation evaluation = HcadDetectionEvaluation.builder()
                .evaluationId("eval-2")
                .mode("SHADOW")
                .triggeredLlm(true)
                .duplicateSuppressed(false)
                .outcomeClass("UNKNOWN")
                .build();
        when(repository.findById("eval-2")).thenReturn(Optional.of(evaluation));
        HcadEvaluationWriter writer = new HcadEvaluationWriter(repository, new ObjectMapper());

        writer.markDecided(
                "eval-2",
                "event-2",
                "ALLOW",
                "CHALLENGE",
                0.12d,
                0.88d,
                123L,
                "FP");

        assertThat(evaluation.getEventId()).isEqualTo("event-2");
        assertThat(evaluation.getLlmAction()).isEqualTo("ALLOW");
        assertThat(evaluation.getLlmProposedAction()).isEqualTo("CHALLENGE");
        assertThat(evaluation.getLlmRiskScore()).isEqualTo(0.12d);
        assertThat(evaluation.getLlmConfidence()).isEqualTo(0.88d);
        assertThat(evaluation.getLlmLatencyMs()).isEqualTo(123L);
        assertThat(evaluation.getOutcomeClass()).isEqualTo("FP");
        assertThat(evaluation.getDecidedAt()).isNotNull();
        verify(repository).save(evaluation);
    }

    @Test
    @DisplayName("recordObservedDecision should persist Protectable LLM observation for HCAD non-trigger")
    void recordObservedDecision_shouldPersistObservationFields() {
        HcadDetectionEvaluationRepository repository = mock(HcadDetectionEvaluationRepository.class);
        when(repository.save(any(HcadDetectionEvaluation.class))).thenAnswer(invocation -> invocation.getArgument(0));
        HcadEvaluationWriter writer = new HcadEvaluationWriter(repository, new ObjectMapper());
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-observed")
                .userId("bob")
                .sourceIp("203.0.113.20")
                .metadata(Map.of(
                        HcadPreProtectablePromotionAttributes.METADATA_EVALUATED, true,
                        HcadPreProtectablePromotionAttributes.METADATA_MODE, "SHADOW",
                        HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE, 35,
                        HcadPreProtectablePromotionAttributes.METADATA_BAND, "MEDIUM",
                        HcadPreProtectablePromotionAttributes.METADATA_ELIGIBLE, false,
                        HcadPreProtectablePromotionAttributes.METADATA_REASON_CODES, List.of("REQUEST_BURST"),
                        HcadPreProtectablePromotionAttributes.METADATA_RAW_SIGNALS, Map.of("requestBurst", 12),
                        "requestId", "request-observed",
                        "httpMethod", "POST",
                        "requestPath", "/admin/users"))
                .build();

        String evaluationId = writer.recordObservedDecision(
                event,
                "BLOCK",
                "BLOCK",
                0.91d,
                0.88d,
                155L,
                HcadOutcomeClassifier.FALSE_NEGATIVE);

        ArgumentCaptor<HcadDetectionEvaluation> captor = ArgumentCaptor.forClass(HcadDetectionEvaluation.class);
        verify(repository).save(captor.capture());
        HcadDetectionEvaluation saved = captor.getValue();
        assertThat(evaluationId).isNotBlank();
        assertThat(saved.getEvaluationId()).isEqualTo(evaluationId);
        assertThat(saved.getEventId()).isEqualTo("event-observed");
        assertThat(saved.getMode()).isEqualTo("SHADOW");
        assertThat(saved.getUserId()).isEqualTo("bob");
        assertThat(saved.getTriggeredLlm()).isFalse();
        assertThat(saved.getRequestPath()).isEqualTo("/admin/users");
        assertThat(saved.getEarlyAnalysisScore()).isEqualTo(35);
        assertThat(saved.getOutcomeClass()).isEqualTo("FN");
        assertThat(saved.getLlmAction()).isEqualTo("BLOCK");
        assertThat(saved.getDecidedAt()).isNotNull();
        assertThat(saved.getReasonCodes()).contains("REQUEST_BURST");
        assertThat(saved.getNonTriggerReason()).isEqualTo("NO_TRUSTED_RISK_SIGNAL");
        assertThat(saved.getEvidenceGapCodes()).contains("TRUSTED_ANCHOR_ABSENT");
        assertThat(saved.getTriggerDecisionReason()).isEqualTo("OBSERVED_WITH_LLM_DECISION");
        assertThat(saved.getSignalSnapshotJson()).contains("requestBurst");
    }

    private PendingAnomalyEvidenceReport report() {
        return new PendingAnomalyEvidenceReport(
                true,
                "alice",
                "ctx-1",
                "base-1",
                "request-1",
                "session-1",
                "/admin/reports",
                "GET",
                "203.0.113.10",
                72,
                "REDLINE",
                true,
                "hcad-promotion-v2-trusted-projection",
                List.of("FAILED_LOGIN_BURST"),
                List.of("REQUEST_BURST"),
                List.of("FAILED_LOGIN_BURST", "REQUEST_BURST"),
                "candidate",
                "risk-1",
                Map.of(
                        "actorSessionKey", "actor-1",
                        "windowId", "window-1",
                        "triggerScope", "SESSION_WINDOW",
                        "requestCount", 3,
                        "duplicateSuppressedCount", 2,
                        "resourceFamilies", List.of("/admin/reports"),
                        "samplePaths", List.of("/admin/reports", "/admin/menu"),
                        "ignoredInputs", Map.of("header.X-Contexa-Test-Run-Id", "run-evidence-1"),
                        "signalProvenance", Map.of("failedLoginBurst", "STORE_DERIVED")));
    }
}
