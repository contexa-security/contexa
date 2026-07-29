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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcOperations;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AiSecurityDecisionObservationWriterTest {

    @Test
    @DisplayName("Protectable LLM decision should store one neutral observation with audit fields")
    void recordDecision_protectableDecision_shouldStoreNeutralObservation() {
        JdbcOperations jdbcOperations = jdbcOperations();
        AiSecurityDecisionObservationWriter writer = new AiSecurityDecisionObservationWriter(
                () -> jdbcOperations,
                new ObjectMapper(),
                "openai",
                "gpt-5-nano");
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-protectable")
                .userId("user-1")
                .sessionId("session-1")
                .metadata(Map.of(
                        "protectableDeclared", true,
                        "requestId", "request-1",
                        "httpMethod", "GET",
                        "requestPath", "/protected/resource",
                        "resourceId", "resource-1"))
                .build();
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action(ZeroTrustAction.CHALLENGE.name())
                .proposedAction(ZeroTrustAction.CHALLENGE.name())
                .llmAuditRiskScore(0.32d)
                .llmAuditConfidence(0.82d)
                .processingTimeMs(123L)
                .llmDecisionPresent(true)
                .build();

        String observationId = writer.recordDecision(event, result, ZeroTrustAction.CHALLENGE);

        assertThat(observationId).isNotBlank();
        Object[] args = firstInsertArgs(jdbcOperations);
        assertThat(args[10]).isEqualTo("PROTECTABLE");
        assertThat(args[11]).isEqualTo("NOT_APPLICABLE");
        assertThat(args[12]).isNull();
        assertThat(args[16]).isEqualTo("openai");
        assertThat(args[17]).isEqualTo("gpt-5-nano");
        assertThat(args[19]).isEqualTo("CHALLENGE");
        assertThat(args[21]).isEqualTo(0.32d);
        assertThat(args[22]).isEqualTo(0.82d);
        assertThat(args[23]).isEqualTo(123L);
        assertThat(args[39]).isEqualTo("NOT_APPLICABLE");
        assertThat(args[41]).isEqualTo(true);
        verify(jdbcOperations, times(1)).update(anyString(), any(Object[].class));
    }

    @Test
    @DisplayName("Technical fallback should retain failure classification and audit data")
    void recordDecision_technicalFallback_shouldRetainFailureAudit() {
        JdbcOperations jdbcOperations = jdbcOperations();
        AiSecurityDecisionObservationWriter writer =
                new AiSecurityDecisionObservationWriter(() -> jdbcOperations, new ObjectMapper());
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-fallback")
                .userId("user-fallback")
                .metadata(Map.of("requestId", "request-fallback"))
                .build();
        ProcessingResult result = ProcessingResult.builder()
                .success(false)
                .action(ZeroTrustAction.BLOCK.name())
                .llmDecisionPresent(false)
                .technicalFallbackApplied(true)
                .technicalFallbackCategory("JSON_PARSE_ERROR")
                .technicalFallbackReason("structured response parse failed")
                .processingTimeMs(17L)
                .build();

        writer.recordDecision(event, result, ZeroTrustAction.PENDING_ANALYSIS);

        Object[] args = firstInsertArgs(jdbcOperations);
        assertThat(args[19]).isEqualTo("PENDING_ANALYSIS");
        assertThat(args[23]).isEqualTo(17L);
        assertThat(args[36]).isEqualTo("PARSER_FAILURE");
        assertThat(args[37]).isEqualTo("JSON_PARSE_ERROR");
        assertThat(args[39]).isEqualTo("NOT_APPLICABLE");
        assertThat(args[41]).isEqualTo(false);
    }

    @Test
    @DisplayName("Missing JDBC should leave the application flow unchanged")
    void recordDecision_withoutJdbc_shouldReturnNull() {
        AiSecurityDecisionObservationWriter writer =
                new AiSecurityDecisionObservationWriter(() -> null, new ObjectMapper());
        SecurityEvent event = SecurityEvent.builder().eventId("event-no-jdbc").build();

        assertThat(writer.recordDecision(event, null, ZeroTrustAction.PENDING_ANALYSIS)).isNull();
    }

    private JdbcOperations jdbcOperations() {
        JdbcOperations jdbcOperations = mock(JdbcOperations.class);
        when(jdbcOperations.update(anyString(), any(Object[].class))).thenReturn(1);
        return jdbcOperations;
    }

    private Object[] firstInsertArgs(JdbcOperations jdbcOperations) {
        ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Object[]> argsCaptor = ArgumentCaptor.forClass(Object[].class);
        verify(jdbcOperations, times(1)).update(sqlCaptor.capture(), argsCaptor.capture());
        List<String> sqlValues = sqlCaptor.getAllValues();
        List<Object[]> argValues = argsCaptor.getAllValues();
        for (int i = 0; i < sqlValues.size(); i++) {
            if (sqlValues.get(i).contains("INSERT INTO ai_security_decision_observation")) {
                return argValues.get(i);
            }
        }
        throw new AssertionError("No AI security decision observation insert captured");
    }
}
