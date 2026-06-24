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
import io.contexa.contexacore.hcad.projection.HcadBaselineComparison;
import io.contexa.contexacore.hcad.trigger.HcadPreTriggerMode;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyEvidenceReport;
import io.contexa.contexacore.hcad.trigger.window.HcadObservationWindowLease;
import io.contexa.contexacore.repository.HcadDetectionEvaluationRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcOperations;

import java.time.Instant;
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
        assertThat(saved.getScoreBreakdownJson()).contains("finalScore", "72", "REDLINE");
        assertThat(saved.getScoreBreakdownJson()).contains(
                "structuredScore",
                "semanticEvidenceScore",
                "normalSuppressionScore",
                "eligibleQuorum",
                "scoreFormula");
        assertThat(saved.getSignalExplanationsJson()).contains(
                "FAILED_LOGIN_BURST",
                "REQUEST_BURST",
                "condition",
                "unmetReason",
                "Repeated failed login",
                "Short-time request increase");
        assertThat(saved.getContextExplanationJson()).contains("alice", "/admin/reports", "request-1");
        assertThat(saved.getBaselineExplanationJson()).contains("available", "false");
        assertThat(saved.getSemanticEvidenceExplanationJson()).contains("SEMANTIC_EVIDENCE_NOT_RECORDED");
        assertThat(saved.getFreshnessExplanationJson()).contains("window-1", "duplicateSuppressedCount");
        assertThat(saved.getTriggerExplanationJson()).contains("TRIGGER_CANDIDATE", "risk-1");
    }

    @Test
    @DisplayName("recordCandidate should explain zero score without vague normal-pattern wording")
    void recordCandidate_zeroScore_shouldPersistConcreteReason() {
        HcadDetectionEvaluationRepository repository = mock(HcadDetectionEvaluationRepository.class);
        when(repository.save(any(HcadDetectionEvaluation.class))).thenAnswer(invocation -> invocation.getArgument(0));
        HcadEvaluationWriter writer = new HcadEvaluationWriter(repository, new ObjectMapper());

        writer.recordCandidate(HcadPreTriggerMode.SHADOW, PendingAnomalyEvidenceReport.noTrigger(
                "alice",
                "ctx-1",
                "base-1",
                "request-zero",
                "session-1",
                "/admin/dashboard",
                "GET",
                "203.0.113.10",
                0,
                "LOW",
                false,
                "hcad-promotion-v2-trusted-projection",
                List.of(),
                List.of(),
                List.of(),
                "no trusted signal",
                Map.of("actorSessionKey", "actor-1", "windowId", "window-1")));

        ArgumentCaptor<HcadDetectionEvaluation> captor = ArgumentCaptor.forClass(HcadDetectionEvaluation.class);
        verify(repository).save(captor.capture());
        HcadDetectionEvaluation saved = captor.getValue();
        assertThat(saved.getScoreBreakdownJson()).contains(
                "scoreInterpretation",
                "NO_APPLIED_TRUSTED_RISK_SIGNAL",
                "No trusted risk signal contributed");
        assertThat(saved.getTriggerExplanationJson()).contains(
                "TRUSTED_ANCHOR_ABSENT",
                "SUPPORTING_SIGNAL_ABSENT");
    }

    @Test
    @DisplayName("recordCandidate JDBC insert should include queryable baseline evidence columns")
    void recordCandidate_jdbcInsert_shouldIncludeBaselineEvidenceColumns() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        HcadEvaluationWriter writer = new HcadEvaluationWriter(jdbcOperations, new ObjectMapper());

        writer.recordCandidate(HcadPreTriggerMode.SHADOW, report());

        ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Object[]> argsCaptor = ArgumentCaptor.forClass(Object[].class);
        verify(jdbcOperations).update(sqlCaptor.capture(), argsCaptor.capture());
        assertThat(sqlCaptor.getValue())
                .contains("score_breakdown_json")
                .contains("signal_explanations_json")
                .contains("context_explanation_json")
                .contains("baseline_explanation_json")
                .contains("semantic_evidence_explanation_json")
                .contains("freshness_explanation_json")
                .contains("trigger_explanation_json");
        Object[] args = argsCaptor.getValue();
        assertThat(args).hasSize(67);
        assertThat(args[4]).isEqualTo("run-evidence-1");
        assertThat(args[32]).isEqualTo(false);
        assertThat(args[33]).isEqualTo(false);
        assertThat(args[34]).isEqualTo(0L);
        assertThat(args[35]).isEqualTo(0);
        assertThat(args[36]).isEqualTo(0);
        assertThat(args[37]).isEqualTo(0);
        assertThat(args[38]).isEqualTo(0.0d);
        assertThat(args[40]).isEqualTo("{}");
        assertThat(args[41]).isEqualTo("{}");
        assertThat(args[45]).asString().contains("finalScore", "72");
        assertThat(args[46]).asString().contains(
                "FAILED_LOGIN_BURST",
                "source_field_path",
                "session.failedLoginAttempts",
                "STORE_DERIVED",
                "scoringAllowed");
        assertThat(args[47]).asString().contains("/admin/reports");
        assertThat(args[48]).asString().contains("available");
        assertThat(args[49]).asString().contains("SEMANTIC_EVIDENCE_NOT_RECORDED");
        assertThat(args[50]).asString().contains("duplicateSuppressedCount");
        assertThat(args[51]).asString().contains("TRIGGER_CANDIDATE");
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
    @DisplayName("recordCandidate should persist explainable baseline dimension details")
    void recordCandidate_shouldPersistBaselineExplanationDetails() {
        HcadDetectionEvaluationRepository repository = mock(HcadDetectionEvaluationRepository.class);
        when(repository.save(any(HcadDetectionEvaluation.class))).thenAnswer(invocation -> invocation.getArgument(0));
        HcadEvaluationWriter writer = new HcadEvaluationWriter(repository, new ObjectMapper());
        Instant lastUpdated = Instant.parse("2026-06-24T00:00:00Z");
        HcadBaselineComparison baselineComparison = new HcadBaselineComparison(
                true,
                true,
                25L,
                20,
                4,
                2,
                0.50d,
                true,
                List.of("accessHour", "browser"),
                List.of("ipBand", "pathFamily"),
                List.of(),
                Map.of("ipBand", "203.0.113", "pathFamily", "/admin/reports"),
                Map.of("normalIpBands", List.of("10.0.0"), "frequentPaths", List.of("/dashboard")),
                lastUpdated);

        writer.recordCandidate(HcadPreTriggerMode.SHADOW, PendingAnomalyEvidenceReport.noTrigger(
                "alice",
                "ctx-1",
                "base-1",
                "request-baseline",
                "session-1",
                "/admin/reports",
                "GET",
                "203.0.113.10",
                20,
                "LOW",
                false,
                "hcad-promotion-v2-trusted-projection",
                List.of(),
                List.of("BASELINE_MATERIAL_MISMATCH"),
                List.of("BASELINE_MATERIAL_MISMATCH"),
                "baseline mismatch",
                Map.of("baselineComparison", baselineComparison)));

        ArgumentCaptor<HcadDetectionEvaluation> captor = ArgumentCaptor.forClass(HcadDetectionEvaluation.class);
        verify(repository).save(captor.capture());
        HcadDetectionEvaluation saved = captor.getValue();
        assertThat(saved.getBaselineExplanationJson()).contains(
                "lastUpdated",
                "2026-06-24T00:00:00Z",
                "dimensionExplanations",
                "IP band",
                "Screen/API family",
                "weight");
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
        assertThat(evaluation.getTriggerExplanationJson()).contains("TRIGGER_PUBLISHED", "modeSemantics");
        assertThat(evaluation.getTriggeredAt()).isNotNull();
        verify(repository).save(evaluation);
    }

    @Test
    @DisplayName("markTriggered JDBC should update trigger explanation json")
    void markTriggered_jdbc_shouldUpdateTriggerExplanation() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        HcadEvaluationWriter writer = new HcadEvaluationWriter(jdbcOperations, new ObjectMapper());

        writer.markTriggered("eval-1");

        ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Object[]> argsCaptor = ArgumentCaptor.forClass(Object[].class);
        verify(jdbcOperations).update(sqlCaptor.capture(), argsCaptor.capture());
        assertThat(sqlCaptor.getValue()).contains("trigger_explanation_json");
        assertThat(argsCaptor.getValue()[0]).asString().contains("TRIGGER_PUBLISHED", "modeSemantics");
    }

    @Test
    @DisplayName("markDuplicateSuppressed should record existing evaluation id and suppression scope")
    void markDuplicateSuppressed_jdbc_shouldRecordExistingEvaluationId() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        HcadEvaluationWriter writer = new HcadEvaluationWriter(jdbcOperations, new ObjectMapper());

        writer.markDuplicateSuppressed("eval-window-1");

        ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Object[]> argsCaptor = ArgumentCaptor.forClass(Object[].class);
        verify(jdbcOperations).update(sqlCaptor.capture(), argsCaptor.capture());

        assertThat(sqlCaptor.getValue()).contains("duplicate_suppressed_count", "trigger_explanation_json");
        assertThat(argsCaptor.getValue()[0]).asString().contains(
                "DUPLICATE_SUPPRESSED",
                "existingEvaluationId",
                "eval-window-1",
                "ACTOR_WINDOW",
                "modeSemantics");
    }

    @Test
    @DisplayName("markTriggerSuppressed should record non-trigger reason with mode semantics")
    void markTriggerSuppressed_jdbc_shouldRecordReason() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        HcadEvaluationWriter writer = new HcadEvaluationWriter(jdbcOperations, new ObjectMapper());

        writer.markTriggerSuppressed("eval-low-risk", "LOW_RISK");

        ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Object[]> argsCaptor = ArgumentCaptor.forClass(Object[].class);
        verify(jdbcOperations).update(sqlCaptor.capture(), argsCaptor.capture());

        assertThat(sqlCaptor.getValue()).contains("trigger_explanation_json");
        assertThat(argsCaptor.getValue()[0]).isEqualTo("LOW_RISK");
        assertThat(argsCaptor.getValue()[1]).isEqualTo("LOW_RISK");
        assertThat(argsCaptor.getValue()[2]).asString().contains("LOW_RISK", "triggeredLlm", "modeSemantics");
    }

    @Test
    @DisplayName("markProtectableObserved should record reused Protectable LLM trigger")
    void markProtectableObserved_reusedProtectableLlm_shouldUpdateHcadRow() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        HcadEvaluationWriter writer = new HcadEvaluationWriter(jdbcOperations, new ObjectMapper());

        writer.markProtectableObserved(
                "eval-combined",
                "hcad.live.vendor.export",
                "/contexa/test/hcad/live/vendors/{vendorId}/export",
                "GET",
                true);

        ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Object[]> argsCaptor = ArgumentCaptor.forClass(Object[].class);
        verify(jdbcOperations).update(sqlCaptor.capture(), argsCaptor.capture());

        assertThat(sqlCaptor.getValue())
                .contains("protectable_observed = true")
                .contains("triggered_llm = true")
                .contains("non_trigger_reason = NULL")
                .contains("trigger_decision_reason = 'PROTECTABLE_LLM_REUSED'")
                .contains("trigger_explanation_json");
        Object[] args = argsCaptor.getValue();
        assertThat(args[0]).isEqualTo("hcad.live.vendor.export");
        assertThat(args[1]).isEqualTo("/contexa/test/hcad/live/vendors/{vendorId}/export");
        assertThat(args[2]).isEqualTo("GET");
        assertThat(args[3]).asString().contains("HCAD_AND_PROTECTABLE", "PROTECTABLE_LLM_REUSED", "mergeExplanation");
        assertThat(args[5]).isEqualTo("eval-combined");
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
        assertThat(saved.getScoreBreakdownJson()).contains("finalScore", "35");
        assertThat(saved.getSignalExplanationsJson()).contains("REQUEST_BURST");
        assertThat(saved.getContextExplanationJson()).contains("bob", "/admin/users", "request-observed");
        assertThat(saved.getBaselineExplanationJson()).contains("available", "false");
        assertThat(saved.getSemanticEvidenceExplanationJson()).contains("SEMANTIC_EVIDENCE_NOT_RECORDED");
        assertThat(saved.getTriggerExplanationJson()).contains("OBSERVED_WITH_LLM_DECISION");
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
                Map.ofEntries(
                        Map.entry("actorSessionKey", "actor-1"),
                        Map.entry("windowId", "window-1"),
                        Map.entry("triggerScope", "SESSION_WINDOW"),
                        Map.entry("requestCount", 3),
                        Map.entry("duplicateSuppressedCount", 2),
                        Map.entry("resourceFamilies", List.of("/admin/reports")),
                        Map.entry("samplePaths", List.of("/admin/reports", "/admin/menu")),
                        Map.entry("ignoredInputs", Map.of("header.X-Contexa-Test-Run-Id", "run-evidence-1")),
                        Map.entry("structuredScore", 60),
                        Map.entry("semanticEvidenceScore", 12),
                        Map.entry("semanticNormalSuppressionScore", 0),
                        Map.entry("semanticEvidenceScoreApplied", 12),
                        Map.entry("scoringThresholds", Map.of("redlineScore", 70, "highRiskScore", 55)),
                        Map.entry("eligibleQuorum", Map.of(
                                "requiresAnchorSignal", true,
                                "requiresCorroboratingSignal", true,
                                "minimumScore", 70,
                                "actualAnchorCount", 1,
                                "actualCorroboratingCount", 1,
                                "actualScore", 72)),
                        Map.entry("eligibleFalseReasons", List.of()),
                        Map.entry("scoreFormula", Map.of(
                                "expression", "bounded(structuredScore + semanticEvidenceScore - normalSuppressionScore)",
                                "finalScore", 72)),
                        Map.entry("signalProvenance", Map.of(
                                "failedLoginBurst", "STORE_DERIVED",
                                "requestBurst", "STORE_DERIVED"))));
    }
}
