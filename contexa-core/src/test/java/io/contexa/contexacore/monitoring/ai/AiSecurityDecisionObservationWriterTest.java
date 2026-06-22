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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcOperations;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class AiSecurityDecisionObservationWriterTest {

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
        assertThat(args[10]).isEqualTo("HCAD_PRE_TRIGGER");
        assertThat(args[11]).isEqualTo("HCAD_ONLY");
        assertThat(args[36]).isEqualTo("TP");
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
        assertThat(args[10]).isEqualTo("PROTECTABLE");
        assertThat(args[11]).isEqualTo("PROTECTABLE_ONLY");
        assertThat(args[36]).isEqualTo("TN");
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
        assertThat(args[10]).isEqualTo("HCAD_PRE_TRIGGER");
        assertThat(args[11]).isEqualTo("HCAD_ONLY");
        assertThat(args[36]).isEqualTo("FP");
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
        assertThat(args[10]).isEqualTo("HCAD_PRE_TRIGGER");
        assertThat(args[11]).isEqualTo("HCAD_AND_PROTECTABLE");
        assertThat(args[19]).isEqualTo("hcad.extreme.allow");
        assertThat(args[36]).isEqualTo("FP");
        Object[] correlationArgs = firstInsertArgs(jdbcOperations, "hcad_llm_decision_correlation");
        assertThat(correlationArgs[8]).isEqualTo("HCAD_AND_PROTECTABLE");
        assertThat(correlationArgs[9]).isEqualTo("FP");
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
        assertThat(args[10]).isEqualTo("PROTECTABLE");
        assertThat(args[11]).isEqualTo("PROTECTABLE_ONLY");
        assertThat(args[36]).isEqualTo("FN");
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
        assertThat(args[33]).isEqualTo(expectedFailureType);
        assertThat(args[36]).isEqualTo(expectedOutcome);
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
