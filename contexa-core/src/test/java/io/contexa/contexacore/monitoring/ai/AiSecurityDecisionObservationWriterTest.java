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

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionOutputContract;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AiSecurityDecisionObservationWriterTest {

    /** W4-3: the observation keeps the reason codes next to the final reasoning. */
    @Test
    void recordDecision_keepsTheReasonCodes() {
        JdbcOperations jdbcOperations = jdbcOperations();
        AiSecurityDecisionObservationWriter writer = new AiSecurityDecisionObservationWriter(
                () -> jdbcOperations, new ObjectMapper(), "openai", "gpt-6-luna");
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-w43")
                .userId("user-1")
                .sessionId("session-1")
                .metadata(Map.of("protectableDeclared", true, "requestId", "request-w43"))
                .build();
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action(ZeroTrustAction.CHALLENGE.name())
                .reasoning("The export time differs from usual.")
                .reasonCodes(List.of(new SecurityDecisionOutputContract.Citation("DEVIATION_TIME", "F1")))
                .llmDecisionPresent(true)
                .build();

        writer.recordDecision(event, result, ZeroTrustAction.CHALLENGE);

        assertThat(firstInsertArgs(jdbcOperations).get("metadata_json")).asString()
                .contains("\"finalDecisionReasonCodes\":[{\"code\":\"DEVIATION_TIME\",\"fact\":\"F1\"}]");
    }

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
                .sourceIp("192.0.2.10")
                .userAgent("Contexa-Test-Agent")
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
        Map<String, Object> args = firstInsertArgs(jdbcOperations);
        assertThat(args.get("trigger_source")).isEqualTo("PROTECTABLE");
        assertThat(args.get("context_binding_hash")).asString().isNotBlank();
        assertThat(args.get("trigger_relation")).isEqualTo("NOT_APPLICABLE");
        assertThat(args.get("decision_boundary_mode")).isNull();
        assertThat(args.get("model_provider")).isEqualTo("openai");
        assertThat(args.get("model_id")).isEqualTo("gpt-5-nano");
        assertThat(args.get("final_action")).isEqualTo("CHALLENGE");
        assertThat(args.get("llm_risk_score")).isEqualTo(0.32d);
        assertThat(args.get("llm_confidence")).isEqualTo(0.82d);
        assertThat(args.get("llm_latency_ms")).isEqualTo(123L);
        assertThat(args.get("metadata_json")).asString().contains("\"contextBindingHash\"");
        assertThat(args.get("outcome_class")).isEqualTo("NOT_APPLICABLE");
        assertThat(args.get("success")).isEqualTo(true);
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

        Map<String, Object> args = firstInsertArgs(jdbcOperations);
        assertThat(args.get("final_action")).isEqualTo("PENDING_ANALYSIS");
        assertThat(args.get("llm_latency_ms")).isEqualTo(17L);
        assertThat(args.get("failure_type")).isEqualTo("PARSER_FAILURE");
        assertThat(args.get("fallback_category")).isEqualTo("JSON_PARSE_ERROR");
        assertThat(args.get("outcome_class")).isEqualTo("NOT_APPLICABLE");
        assertThat(args.get("success")).isEqualTo(false);
    }

    @Test
    @DisplayName("Why the provider gave no decision is kept as the failure type")
    void recordDecision_providerAnswerFailure_shouldKeepItsCategory() {
        for (String category : new String[]{"OUTPUT_TRUNCATED", "PROVIDER_REFUSAL", "PROVIDER_OVERLOADED",
                "PROVIDER_REQUEST_REJECTED"}) {
            JdbcOperations jdbcOperations = jdbcOperations();
            AiSecurityDecisionObservationWriter writer =
                    new AiSecurityDecisionObservationWriter(() -> jdbcOperations, new ObjectMapper());
            SecurityEvent event = SecurityEvent.builder()
                    .eventId("event-" + category)
                    .userId("user-provider")
                    .metadata(Map.of("requestId", "request-" + category,
                            "securityDecisionParseFailureCategory", category,
                            "securityDecisionFallbackReason", "LLM_EXECUTION_FAILED"))
                    .build();
            ProcessingResult result = ProcessingResult.builder()
                    .success(false)
                    .action(ZeroTrustAction.CHALLENGE.name())
                    .llmDecisionPresent(false)
                    .technicalFallbackApplied(true)
                    .technicalFallbackCategory(category)
                    .technicalFallbackReason("LLM_EXECUTION_FAILED")
                    .processingTimeMs(11L)
                    .build();

            writer.recordDecision(event, result, ZeroTrustAction.CHALLENGE);

            assertThat(firstInsertArgs(jdbcOperations).get("failure_type")).as(category).isEqualTo(category);
        }
    }

    @Test
    @DisplayName("Response-action fallback should be recorded as parser failure, not technical fallback")
    void recordDecision_responseActionFallback_shouldClassifyParserFailure() {
        JdbcOperations jdbcOperations = jdbcOperations();
        AiSecurityDecisionObservationWriter writer =
                new AiSecurityDecisionObservationWriter(() -> jdbcOperations, new ObjectMapper());
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-response-fallback")
                .userId("user-response-fallback")
                .metadata(Map.of("requestId", "request-response-fallback"))
                .build();
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action(ZeroTrustAction.CHALLENGE.name())
                .proposedAction(ZeroTrustAction.CHALLENGE.name())
                .llmDecisionPresent(false)
                .technicalFallbackApplied(false)
                .responseActionFallbackApplied(true)
                .responseActionFallbackCategory("ACTION_FORMAT_INVALID")
                .responseActionFallbackReason("Security decision response action was repaired")
                .responseActionFallbackAction(ZeroTrustAction.CHALLENGE.name())
                .processingTimeMs(19L)
                .build();

        writer.recordDecision(event, result, ZeroTrustAction.CHALLENGE);

        Map<String, Object> args = firstInsertArgs(jdbcOperations);
        assertThat(args.get("llm_decision_present")).isEqualTo(false);
        assertThat(args.get("parser_failure")).isEqualTo(true);
        assertThat(args.get("technical_fallback")).isEqualTo(false);
        assertThat(args.get("failure_type")).isEqualTo("PARSER_FAILURE");
        assertThat(args.get("fallback_category")).isEqualTo("ACTION_FORMAT_INVALID");
        assertThat(args.get("fallback_reason")).asString().contains("response action was repaired");
        assertThat(args.get("success")).isEqualTo(false);
    }
    /**
     * N-OUT-1 (G1-14): when the model's answer never came (an outage, a contract violation left after the retry) and the
     * parser filled the action, the observation is a technical fallback, not a parser failure.
     */
    @Test
    void anAnswerThatNeverCameIsATechnicalFallbackNotAParserFailure() {
        for (String category : List.of("MODEL_UNAVAILABLE", "VALIDATION_FAILED")) {
            JdbcOperations jdbcOperations = jdbcOperations();
            AiSecurityDecisionObservationWriter writer =
                    new AiSecurityDecisionObservationWriter(() -> jdbcOperations, new ObjectMapper());
            SecurityEvent event = SecurityEvent.builder()
                    .eventId("event-no-answer-" + category)
                    .userId("user-no-answer")
                    .metadata(Map.of("requestId", "request-no-answer-" + category,
                            "rawExecutionSucceeded", false,
                            "securityDecisionParsingFallbackApplied", true,
                            "structuredOutputFailureCategory", category))
                    .build();
            ProcessingResult result = ProcessingResult.builder()
                    .success(true)
                    .action(ZeroTrustAction.CHALLENGE.name())
                    .llmDecisionPresent(false)
                    .technicalFallbackApplied(true)
                    .technicalFallbackCategory(category)
                    .processingTimeMs(21L)
                    .build();

            writer.recordDecision(event, result, ZeroTrustAction.CHALLENGE);

            Map<String, Object> args = firstInsertArgs(jdbcOperations);
            assertThat(args.get("technical_fallback")).as(category).isEqualTo(true);
            assertThat(args.get("parser_failure")).as(category).isEqualTo(false);
            assertThat(args.get("fallback_category")).as(category).isEqualTo(category);
            assertThat(args.get("failure_type")).as(category).isNotEqualTo("PARSER_FAILURE");
        }
    }

    /**
     * W4-7 (inventory 6 bundle 30): the call time column reads providerCallMs, and the time is not copied again as a
     * latency key into the stored metadata.
     */
    @Test
    void theCallTimeColumnReadsTheProviderCallTimeAndIsNotCopiedAgain() {
        JdbcOperations jdbcOperations = jdbcOperations();
        AiSecurityDecisionObservationWriter writer =
                new AiSecurityDecisionObservationWriter(() -> jdbcOperations, new ObjectMapper());
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-provider-call")
                .userId("user-provider-call")
                .metadata(Map.of("requestId", "request-provider-call", "providerCallMs", 321L))
                .build();
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action(ZeroTrustAction.ALLOW.name())
                .llmDecisionPresent(true)
                .processingTimeMs(400L)
                .build();

        writer.recordDecision(event, result, ZeroTrustAction.ALLOW);

        Map<String, Object> args = firstInsertArgs(jdbcOperations);
        assertThat(args.get("openai_call_ms")).isEqualTo(321L);
        assertThat(String.valueOf(args.get("metadata_json")))
                .doesNotContain("latencyOpenAiCallMs")
                .doesNotContain("latencyProviderCallMs");
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

    private Map<String, Object> firstInsertArgs(JdbcOperations jdbcOperations) {
        ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Object[]> argsCaptor = ArgumentCaptor.forClass(Object[].class);
        verify(jdbcOperations, times(1)).update(sqlCaptor.capture(), argsCaptor.capture());
        List<String> sqlValues = sqlCaptor.getAllValues();
        List<Object[]> argValues = argsCaptor.getAllValues();
        for (int i = 0; i < sqlValues.size(); i++) {
            if (sqlValues.get(i).contains("INSERT INTO ai_security_decision_observation")) {
                String sql = sqlValues.get(i);
                String[] columns = sql.substring(sql.indexOf('(') + 1, sql.indexOf(')')).split(",");
                Object[] values = argValues.get(i);
                assertThat(values).hasSize(columns.length);
                Map<String, Object> row = new LinkedHashMap<>();
                for (int column = 0; column < columns.length; column++) {
                    row.put(columns[column].trim(), values[column]);
                }
                return row;
            }
        }
        throw new AssertionError("No AI security decision observation insert captured");
    }
}
