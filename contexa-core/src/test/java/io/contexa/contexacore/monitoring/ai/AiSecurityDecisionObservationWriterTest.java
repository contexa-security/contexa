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
