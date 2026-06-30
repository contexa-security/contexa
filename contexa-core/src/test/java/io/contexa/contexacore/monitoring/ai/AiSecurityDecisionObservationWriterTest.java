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
package io.contexa.contexacore.monitoring.ai;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionAttributes;
import io.contexa.contexacore.hcad.semantic.HcadSemanticEvidenceRefreshService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcOperations;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AiSecurityDecisionObservationWriterTest {

    @Test
    @DisplayName("Successful LLM decision should refresh HCAD semantic evidence cache after observation storage")
    void recordDecision_successfulDecision_shouldRefreshSemanticEvidence() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        HcadSemanticEvidenceRefreshService refreshService = mock(HcadSemanticEvidenceRefreshService.class);
        AiSecurityDecisionObservationWriter writer =
                new AiSecurityDecisionObservationWriter(
                        () -> jdbcOperations,
                        new ObjectMapper(),
                        "openai",
                        "gpt-5-nano",
                        refreshService);
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-refresh-1")
                .userId("admin")
                .metadata(metadata(Map.of(
                        "triggerSource", "PROTECTABLE",
                        "requestId", "req-refresh-1",
                        "requestPath", "/contexa/admin/users",
                        "resourceId", "/contexa/admin/users"
                )))
                .build();
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action("ALLOW")
                .proposedAction("ALLOW")
                .llmAuditRiskScore(0.08d)
                .llmAuditConfidence(0.91d)
                .llmDecisionPresent(true)
                .processingTimeMs(120L)
                .build();

        writer.recordDecision(event, result, ZeroTrustAction.ALLOW);

        verify(refreshService).refreshAfterDecision(eq(event), anyMap(), eq("ALLOW"));
    }

    @Test
    @DisplayName("Failed LLM decision should not refresh HCAD semantic evidence cache")
    void recordDecision_failedDecision_shouldNotRefreshSemanticEvidence() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        HcadSemanticEvidenceRefreshService refreshService = mock(HcadSemanticEvidenceRefreshService.class);
        AiSecurityDecisionObservationWriter writer =
                new AiSecurityDecisionObservationWriter(
                        () -> jdbcOperations,
                        new ObjectMapper(),
                        "openai",
                        "gpt-5-nano",
                        refreshService);
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-refresh-failure")
                .userId("admin")
                .metadata(metadata(Map.of(
                        "triggerSource", "PROTECTABLE",
                        "requestId", "req-refresh-failure",
                        "requestPath", "/contexa/admin/users",
                        "resourceId", "/contexa/admin/users"
                )))
                .build();
        ProcessingResult result = ProcessingResult.builder()
                .success(false)
                .action("PENDING_ANALYSIS")
                .proposedAction("PENDING_ANALYSIS")
                .errorMessage("LLM timeout")
                .llmDecisionPresent(false)
                .processingTimeMs(15000L)
                .build();

        writer.recordDecision(event, result, ZeroTrustAction.PENDING_ANALYSIS);

        verify(refreshService, never()).refreshAfterDecision(eq(event), anyMap(), anyString());
    }

    @Test
    @DisplayName("Successful CHALLENGE LLM decision should refresh HCAD risk semantic evidence cache")
    void recordDecision_successfulChallengeDecision_shouldRefreshRiskSemanticEvidence() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        HcadSemanticEvidenceRefreshService refreshService = mock(HcadSemanticEvidenceRefreshService.class);
        AiSecurityDecisionObservationWriter writer =
                new AiSecurityDecisionObservationWriter(
                        () -> jdbcOperations,
                        new ObjectMapper(),
                        "openai",
                        "gpt-5-nano",
                        refreshService);
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-refresh-challenge")
                .userId("admin")
                .metadata(metadata(Map.of(
                        "triggerSource", "PROTECTABLE",
                        "requestId", "req-refresh-challenge",
                        "requestPath", "/contexa/admin/users",
                        "resourceId", "/contexa/admin/users"
                )))
                .build();
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action("CHALLENGE")
                .proposedAction("CHALLENGE")
                .llmAuditRiskScore(0.88d)
                .llmAuditConfidence(0.9d)
                .llmDecisionPresent(true)
                .processingTimeMs(120L)
                .build();

        writer.recordDecision(event, result, ZeroTrustAction.CHALLENGE);

        verify(refreshService).refreshAfterDecision(eq(event), anyMap(), eq("CHALLENGE"));
    }

    @Test
    @DisplayName("Successful LLM decision without risk score or confidence should not refresh HCAD semantic evidence cache")
    void recordDecision_successfulDecisionWithoutScoreOrConfidence_shouldNotRefreshSemanticEvidence() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        HcadSemanticEvidenceRefreshService refreshService = mock(HcadSemanticEvidenceRefreshService.class);
        AiSecurityDecisionObservationWriter writer =
                new AiSecurityDecisionObservationWriter(
                        () -> jdbcOperations,
                        new ObjectMapper(),
                        "openai",
                        "gpt-5-nano",
                        refreshService);
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-refresh-no-score")
                .userId("admin")
                .metadata(metadata(Map.of(
                        "triggerSource", "PROTECTABLE",
                        "requestId", "req-refresh-no-score",
                        "requestPath", "/contexa/admin/users",
                        "resourceId", "/contexa/admin/users"
                )))
                .build();
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action("ALLOW")
                .proposedAction("ALLOW")
                .llmDecisionPresent(true)
                .processingTimeMs(120L)
                .build();

        writer.recordDecision(event, result, ZeroTrustAction.ALLOW);

        verify(refreshService, never()).refreshAfterDecision(eq(event), anyMap(), anyString());
    }
    @Test
    @DisplayName("HCAD pre-triggered LLM decision should be stored as HCAD_ONLY TP when LLM reports risk")
    void recordDecision_hcadTriggeredRisk_shouldStoreHcadOnlyTruePositive() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        AiSecurityDecisionObservationWriter writer =
                new AiSecurityDecisionObservationWriter(() -> jdbcOperations, new ObjectMapper());
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-1")
                .userId("admin")
                .metadata(metadata(Map.of(
                        "triggerSource", "HCAD_PRE_TRIGGER",
                        "hcadEvaluationId", "eval-1",
                        "testRunId", "run-evidence-1",
                        "requestId", "req-1",
                        HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE, 85,
                        HcadPreProtectablePromotionAttributes.METADATA_BAND, "HIGH",
                        HcadPreProtectablePromotionAttributes.METADATA_ELIGIBLE, true
                )))
                .build();
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action("BLOCK")
                .proposedAction("BLOCK")
                .llmAuditRiskScore(0.92d)
                .llmAuditConfidence(0.88d)
                .llmDecisionPresent(true)
                .processingTimeMs(120L)
                .build();

        String observationId = writer.recordDecision(event, result, ZeroTrustAction.BLOCK);

        assertThat(observationId).isNotBlank();
        Object[] args = firstInsertArgs(jdbcOperations, "ai_security_decision_observation");
        assertThat(args[4]).isEqualTo("run-evidence-1");
        assertThat(args[11]).isEqualTo("HCAD_PRE_TRIGGER");
        assertThat(args[12]).isEqualTo("HCAD_ONLY");
        assertThat(args[44]).isEqualTo("TP");
    }

    @Test
    @DisplayName("Protectable LLM decision with prior HCAD observation should be stored as PROTECTABLE_ONLY TN when allowed")
    void recordDecision_protectableObservedAllow_shouldStoreProtectableOnlyTrueNegative() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        AiSecurityDecisionObservationWriter writer =
                new AiSecurityDecisionObservationWriter(() -> jdbcOperations, new ObjectMapper());
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-2")
                .userId("admin")
                .metadata(metadata(Map.of(
                        "protectableDeclared", true,
                        "protectableResourceId", "orders.read",
                        "hcadEvaluationId", "eval-2",
                        "requestId", "req-2",
                        HcadPreProtectablePromotionAttributes.METADATA_EVALUATED, true,
                        HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE, 10,
                        HcadPreProtectablePromotionAttributes.METADATA_BAND, "LOW",
                        HcadPreProtectablePromotionAttributes.METADATA_ELIGIBLE, false
                )))
                .build();
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action("ALLOW")
                .proposedAction("ALLOW")
                .llmAuditRiskScore(0.05d)
                .llmAuditConfidence(0.91d)
                .llmDecisionPresent(true)
                .processingTimeMs(95L)
                .build();

        String observationId = writer.recordDecision(event, result, ZeroTrustAction.ALLOW);

        assertThat(observationId).isNotBlank();
        Object[] args = firstInsertArgs(jdbcOperations, "ai_security_decision_observation");
        assertThat(args[11]).isEqualTo("PROTECTABLE");
        assertThat(args[12]).isEqualTo("PROTECTABLE_ONLY");
        assertThat(args[44]).isEqualTo("TN");
    }

    @Test
    @DisplayName("HCAD pre-triggered LLM allow should be stored as HCAD_ONLY FP")
    void recordDecision_hcadTriggeredAllow_shouldStoreFalsePositive() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        AiSecurityDecisionObservationWriter writer =
                new AiSecurityDecisionObservationWriter(() -> jdbcOperations, new ObjectMapper());
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-fp")
                .userId("admin")
                .metadata(metadata(Map.of(
                        "triggerSource", "HCAD_PRE_TRIGGER",
                        "hcadEvaluationId", "eval-fp",
                        "requestId", "req-fp",
                        HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE, 80,
                        HcadPreProtectablePromotionAttributes.METADATA_BAND, "HIGH",
                        HcadPreProtectablePromotionAttributes.METADATA_ELIGIBLE, true
                )))
                .build();
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action("ALLOW")
                .proposedAction("ALLOW")
                .llmAuditRiskScore(0.05d)
                .llmAuditConfidence(0.95d)
                .llmDecisionPresent(true)
                .build();

        String observationId = writer.recordDecision(event, result, ZeroTrustAction.ALLOW);

        assertThat(observationId).isNotBlank();
        Object[] args = firstInsertArgs(jdbcOperations, "ai_security_decision_observation");
        assertThat(args[11]).isEqualTo("HCAD_PRE_TRIGGER");
        assertThat(args[12]).isEqualTo("HCAD_ONLY");
        assertThat(args[44]).isEqualTo("FP");
    }

    @Test
    @DisplayName("Protectable LLM decision with same request HCAD trigger should be stored as HCAD_AND_PROTECTABLE FP when allowed")
    void recordDecision_hcadAndProtectableAllow_shouldStoreCombinedFalsePositive() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        AiSecurityDecisionObservationWriter writer =
                new AiSecurityDecisionObservationWriter(() -> jdbcOperations, new ObjectMapper());
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-combined-fp")
                .userId("admin")
                .metadata(metadata(Map.of(
                        "triggerSource", "HCAD_PRE_TRIGGER",
                        "protectableDeclared", true,
                        "protectableResourceId", "hcad.extreme.allow",
                        "protectableResourceUrl", "/contexa/test/hcad/protectable/allow",
                        "hcadEvaluationId", "eval-combined-fp",
                        "testRunId", "run-evidence-combined-fp",
                        "requestId", "req-combined-fp",
                        HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE, 78,
                        HcadPreProtectablePromotionAttributes.METADATA_BAND, "HIGH",
                        HcadPreProtectablePromotionAttributes.METADATA_ELIGIBLE, true
                )))
                .build();
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action("ALLOW")
                .proposedAction("ALLOW")
                .llmAuditRiskScore(0.04d)
                .llmAuditConfidence(0.94d)
                .llmDecisionPresent(true)
                .build();

        String observationId = writer.recordDecision(event, result, ZeroTrustAction.ALLOW);

        assertThat(observationId).isNotBlank();
        Object[] args = firstInsertArgs(jdbcOperations, "ai_security_decision_observation");
        assertThat(args[4]).isEqualTo("run-evidence-combined-fp");
        assertThat(args[11]).isEqualTo("HCAD_PRE_TRIGGER");
        assertThat(args[12]).isEqualTo("HCAD_AND_PROTECTABLE");
        assertThat(args[20]).isNull();
        assertThat(args[44]).isEqualTo("FP");
        Object[] correlationArgs = firstInsertArgs(jdbcOperations, "hcad_llm_decision_correlation");
        assertThat(correlationArgs[5]).isEqualTo("run-evidence-combined-fp");
        assertThat(correlationArgs[9]).isEqualTo("HCAD_AND_PROTECTABLE");
        assertThat(correlationArgs[10]).isEqualTo("FP");
    }

    @Test
    @DisplayName("Protectable LLM decision with eligible same-request HCAD observation should be stored as HCAD_AND_PROTECTABLE FP when allowed")
    void recordDecision_protectableWithEligibleHcadObservationAllow_shouldStoreCombinedFalsePositive() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        AiSecurityDecisionObservationWriter writer =
                new AiSecurityDecisionObservationWriter(() -> jdbcOperations, new ObjectMapper());
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-protectable-combined-fp")
                .userId("admin")
                .metadata(metadata(Map.ofEntries(
                        Map.entry("triggerSource", "PROTECTABLE"),
                        Map.entry("protectableDeclared", true),
                        Map.entry("protectableResourceId", "hcad.live.vendor.export"),
                        Map.entry("protectableResourceUrl", "/contexa/test/hcad/live/vendors/{vendorId}/export"),
                        Map.entry("hcadEvaluationId", "eval-protectable-combined-fp"),
                        Map.entry("testRunId", "run-protectable-combined-fp"),
                        Map.entry("requestId", "req-protectable-combined-fp"),
                        Map.entry(HcadPreProtectablePromotionAttributes.METADATA_EVALUATED, true),
                        Map.entry(HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE, 70),
                        Map.entry(HcadPreProtectablePromotionAttributes.METADATA_BAND, "REDLINE"),
                        Map.entry(HcadPreProtectablePromotionAttributes.METADATA_ELIGIBLE, true)
                )))
                .build();
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action("ALLOW")
                .proposedAction("ALLOW")
                .llmAuditRiskScore(0.35d)
                .llmAuditConfidence(0.84d)
                .llmDecisionPresent(true)
                .build();

        String observationId = writer.recordDecision(event, result, ZeroTrustAction.ALLOW);

        assertThat(observationId).isNotBlank();
        Object[] args = firstInsertArgs(jdbcOperations, "ai_security_decision_observation");
        assertThat(args[4]).isEqualTo("run-protectable-combined-fp");
        assertThat(args[11]).isEqualTo("PROTECTABLE");
        assertThat(args[12]).isEqualTo("HCAD_AND_PROTECTABLE");
        assertThat(args[44]).isEqualTo("FP");
        Object[] correlationArgs = firstInsertArgs(jdbcOperations, "hcad_llm_decision_correlation");
        assertThat(correlationArgs[5]).isEqualTo("run-protectable-combined-fp");
        assertThat(correlationArgs[9]).isEqualTo("HCAD_AND_PROTECTABLE");
        assertThat(correlationArgs[10]).isEqualTo("FP");
    }

    @Test
    @DisplayName("Protectable LLM risk with eligible same-request HCAD observation should be stored as HCAD_AND_PROTECTABLE TP")
    void recordDecision_protectableWithEligibleHcadObservationRisk_shouldStoreCombinedTruePositive() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        AiSecurityDecisionObservationWriter writer =
                new AiSecurityDecisionObservationWriter(() -> jdbcOperations, new ObjectMapper());
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-protectable-combined-tp")
                .userId("admin")
                .metadata(metadata(Map.ofEntries(
                        Map.entry("triggerSource", "PROTECTABLE"),
                        Map.entry("protectableDeclared", true),
                        Map.entry("protectableResourceId", "hcad.live.finance.invoice"),
                        Map.entry("protectableResourceUrl", "/contexa/test/hcad/live/finance/invoices/{invoiceId}"),
                        Map.entry("hcadEvaluationId", "eval-protectable-combined-tp"),
                        Map.entry("testRunId", "run-protectable-combined-tp"),
                        Map.entry("requestId", "req-protectable-combined-tp"),
                        Map.entry(HcadPreProtectablePromotionAttributes.METADATA_EVALUATED, true),
                        Map.entry(HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE, 90),
                        Map.entry(HcadPreProtectablePromotionAttributes.METADATA_BAND, "REDLINE"),
                        Map.entry(HcadPreProtectablePromotionAttributes.METADATA_ELIGIBLE, true)
                )))
                .build();
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action("CHALLENGE")
                .proposedAction("CHALLENGE")
                .llmAuditRiskScore(0.9d)
                .llmAuditConfidence(0.9d)
                .llmDecisionPresent(true)
                .build();

        String observationId = writer.recordDecision(event, result, ZeroTrustAction.CHALLENGE);

        assertThat(observationId).isNotBlank();
        Object[] args = firstInsertArgs(jdbcOperations, "ai_security_decision_observation");
        assertThat(args[4]).isEqualTo("run-protectable-combined-tp");
        assertThat(args[11]).isEqualTo("PROTECTABLE");
        assertThat(args[12]).isEqualTo("HCAD_AND_PROTECTABLE");
        assertThat(args[44]).isEqualTo("TP");
        Object[] correlationArgs = firstInsertArgs(jdbcOperations, "hcad_llm_decision_correlation");
        assertThat(correlationArgs[5]).isEqualTo("run-protectable-combined-tp");
        assertThat(correlationArgs[9]).isEqualTo("HCAD_AND_PROTECTABLE");
        assertThat(correlationArgs[10]).isEqualTo("TP");
    }

    @Test
    @DisplayName("Protectable LLM decision should use durable HCAD eligible marker when event metadata omits it")
    void recordDecision_protectableWithDurableEligibleHcadObservation_shouldStoreCombinedRelation() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        when(jdbcOperations.queryForObject(
                        contains("trigger_decision_reason = 'PROTECTABLE_LLM_REUSED'"),
                        eq(Boolean.class),
                        eq("eval-durable-combined")))
                .thenReturn(true);
        AiSecurityDecisionObservationWriter writer =
                new AiSecurityDecisionObservationWriter(() -> jdbcOperations, new ObjectMapper());
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-durable-combined")
                .userId("admin")
                .metadata(metadata(Map.of(
                        "triggerSource", "PROTECTABLE",
                        "protectableDeclared", true,
                        "protectableResourceId", "hcad.live.vendor.export",
                        "protectableResourceUrl", "/contexa/test/hcad/live/vendors/{vendorId}/export",
                        "hcadEvaluationId", "eval-durable-combined",
                        "testRunId", "run-durable-combined",
                        "requestId", "req-durable-combined",
                        HcadPreProtectablePromotionAttributes.METADATA_EVALUATED, true,
                        HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE, 70,
                        HcadPreProtectablePromotionAttributes.METADATA_BAND, "REDLINE"
                )))
                .build();
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action("ALLOW")
                .proposedAction("ALLOW")
                .llmAuditRiskScore(0.35d)
                .llmAuditConfidence(0.84d)
                .llmDecisionPresent(true)
                .build();

        String observationId = writer.recordDecision(event, result, ZeroTrustAction.ALLOW);

        assertThat(observationId).isNotBlank();
        Object[] args = firstInsertArgs(jdbcOperations, "ai_security_decision_observation");
        assertThat(args[4]).isEqualTo("run-durable-combined");
        assertThat(args[11]).isEqualTo("PROTECTABLE");
        assertThat(args[12]).isEqualTo("HCAD_AND_PROTECTABLE");
        assertThat(args[17]).isEqualTo(true);
        assertThat(args[44]).isEqualTo("FP");
        Object[] correlationArgs = firstInsertArgs(jdbcOperations, "hcad_llm_decision_correlation");
        assertThat(correlationArgs[5]).isEqualTo("run-durable-combined");
        assertThat(correlationArgs[9]).isEqualTo("HCAD_AND_PROTECTABLE");
        assertThat(correlationArgs[10]).isEqualTo("FP");
        assertThat(correlationArgs[13]).isEqualTo(true);
    }

    @Test
    @DisplayName("Delayed HCAD observation should use durable Protectable merge marker when observation is written later")
    void recordDecision_delayedHcadObservationWithMergeMarker_shouldStoreCombinedRelation() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        when(jdbcOperations.queryForObject(
                        contains("protectable_observed"),
                        eq(Boolean.class),
                        eq("eval-delayed-combined")))
                .thenReturn(true);
        AiSecurityDecisionObservationWriter writer =
                new AiSecurityDecisionObservationWriter(() -> jdbcOperations, new ObjectMapper());
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-delayed-combined")
                .userId("admin")
                .metadata(metadata(Map.of(
                        "triggerSource", "HCAD_PRE_TRIGGER",
                        "hcadEvaluationId", "eval-delayed-combined",
                        "testRunId", "run-evidence-delayed-combined",
                        "requestId", "req-delayed-combined",
                        HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE, 100,
                        HcadPreProtectablePromotionAttributes.METADATA_BAND, "REDLINE",
                        HcadPreProtectablePromotionAttributes.METADATA_ELIGIBLE, true
                )))
                .build();
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action("ALLOW")
                .proposedAction("ALLOW")
                .llmAuditRiskScore(0.05d)
                .llmAuditConfidence(0.95d)
                .llmDecisionPresent(true)
                .build();

        String observationId = writer.recordDecision(event, result, ZeroTrustAction.ALLOW);

        assertThat(observationId).isNotBlank();
        Object[] args = firstInsertArgs(jdbcOperations, "ai_security_decision_observation");
        assertThat(args[4]).isEqualTo("run-evidence-delayed-combined");
        assertThat(args[11]).isEqualTo("HCAD_PRE_TRIGGER");
        assertThat(args[12]).isEqualTo("HCAD_AND_PROTECTABLE");
        assertThat(args[44]).isEqualTo("FP");
        Object[] correlationArgs = firstInsertArgs(jdbcOperations, "hcad_llm_decision_correlation");
        assertThat(correlationArgs[5]).isEqualTo("run-evidence-delayed-combined");
        assertThat(correlationArgs[9]).isEqualTo("HCAD_AND_PROTECTABLE");
    }

    @Test
    @DisplayName("Protectable LLM risk with HCAD observation but no trigger should be stored as FN")
    void recordDecision_protectableObservedRisk_shouldStoreFalseNegative() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        AiSecurityDecisionObservationWriter writer =
                new AiSecurityDecisionObservationWriter(() -> jdbcOperations, new ObjectMapper());
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-fn")
                .userId("admin")
                .metadata(metadata(Map.of(
                        "protectableDeclared", true,
                        "protectableResourceId", "hcad.extreme.challenge",
                        "hcadEvaluationId", "eval-fn",
                        "requestId", "req-fn",
                        HcadPreProtectablePromotionAttributes.METADATA_EVALUATED, true,
                        HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE, 20,
                        HcadPreProtectablePromotionAttributes.METADATA_BAND, "LOW",
                        HcadPreProtectablePromotionAttributes.METADATA_ELIGIBLE, false
                )))
                .build();
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action("CHALLENGE")
                .proposedAction("CHALLENGE")
                .llmAuditRiskScore(0.84d)
                .llmAuditConfidence(0.91d)
                .llmDecisionPresent(true)
                .build();

        String observationId = writer.recordDecision(event, result, ZeroTrustAction.CHALLENGE);

        assertThat(observationId).isNotBlank();
        Object[] args = firstInsertArgs(jdbcOperations, "ai_security_decision_observation");
        assertThat(args[11]).isEqualTo("PROTECTABLE");
        assertThat(args[12]).isEqualTo("PROTECTABLE_ONLY");
        assertThat(args[44]).isEqualTo("FN");
    }

    @Test
    @DisplayName("Parser failure should be stored as UNKNOWN and excluded from precision")
    void recordDecision_parserFailure_shouldStoreUnknown() {
        assertFailureType("parser failure: could not parse response", "PARSER_FAILURE", "UNKNOWN");
    }

    @Test
    @DisplayName("Timeout should be stored as UNKNOWN and excluded from precision")
    void recordDecision_timeout_shouldStoreUnknown() {
        assertFailureType("LLM request timeout", "TIMEOUT", "UNKNOWN");
    }

    @Test
    @DisplayName("Model unavailable should be stored as UNKNOWN and excluded from precision")
    void recordDecision_modelUnavailable_shouldStoreUnknown() {
        assertFailureType("model unavailable", "MODEL_UNAVAILABLE", "UNKNOWN");
    }

    private void assertFailureType(String failureReason, String expectedFailureType, String expectedOutcome) {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        AiSecurityDecisionObservationWriter writer =
                new AiSecurityDecisionObservationWriter(() -> jdbcOperations, new ObjectMapper());
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-" + expectedFailureType)
                .userId("admin")
                .metadata(metadata(Map.of(
                        "triggerSource", "HCAD_PRE_TRIGGER",
                        "hcadEvaluationId", "eval-" + expectedFailureType,
                        "requestId", "req-" + expectedFailureType,
                        HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE, 75,
                        HcadPreProtectablePromotionAttributes.METADATA_BAND, "HIGH",
                        HcadPreProtectablePromotionAttributes.METADATA_ELIGIBLE, true
                )))
                .build();
        ProcessingResult result = ProcessingResult.builder()
                .success(false)
                .errorMessage(failureReason)
                .message(failureReason)
                .llmDecisionPresent(false)
                .technicalFallbackApplied(true)
                .technicalFallbackReason(failureReason)
                .build();

        String observationId = writer.recordDecision(event, result, ZeroTrustAction.PENDING_ANALYSIS);

        assertThat(observationId).isNotBlank();
        Object[] args = firstInsertArgs(jdbcOperations, "ai_security_decision_observation");
        assertThat(args[41]).isEqualTo(expectedFailureType);
        assertThat(args[44]).isEqualTo(expectedOutcome);
    }

    private Map<String, Object> metadata(Map<String, Object> source) {
        return new HashMap<>(source);
    }

    private Object[] firstInsertArgs(JdbcOperations jdbcOperations, String tableName) {
        ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Object[]> argsCaptor = ArgumentCaptor.forClass(Object[].class);
        verify(jdbcOperations, atLeastOnce()).update(sqlCaptor.capture(), argsCaptor.capture());
        List<String> sqlValues = sqlCaptor.getAllValues();
        List<Object[]> argValues = argsCaptor.getAllValues();
        for (int i = 0; i < sqlValues.size(); i++) {
            if (sqlValues.get(i).contains("INSERT INTO " + tableName)) {
                return argValues.get(i);
            }
        }
        throw new AssertionError("No insert captured for table " + tableName);
    }
}

