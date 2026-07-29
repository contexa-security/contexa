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

import io.contexa.contexacore.util.SensitiveValueSanitizer;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcOperations;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;

@Slf4j
public class AiSecurityDecisionObservationWriter {

    private static final String LEGACY_TRIGGER_SOURCE_NOT_APPLICABLE = "UNKNOWN";
    private static final String LEGACY_TRIGGER_RELATION_NOT_APPLICABLE = "NOT_APPLICABLE";
    private static final String LEGACY_OUTCOME_NOT_APPLICABLE = "NOT_APPLICABLE";

    private final Supplier<JdbcOperations> jdbcOperationsSupplier;
    private final ObjectMapper objectMapper;
    private final String defaultModelProvider;
    private final String defaultModelId;

    public AiSecurityDecisionObservationWriter(
            Supplier<JdbcOperations> jdbcOperationsSupplier,
            ObjectMapper objectMapper) {
        this(jdbcOperationsSupplier, objectMapper, null, null);
    }

    public AiSecurityDecisionObservationWriter(
            Supplier<JdbcOperations> jdbcOperationsSupplier,
            ObjectMapper objectMapper,
            String defaultModelProvider,
            String defaultModelId) {
        this.jdbcOperationsSupplier = jdbcOperationsSupplier == null ? () -> null : jdbcOperationsSupplier;
        this.objectMapper = objectMapper;
        this.defaultModelProvider = text(defaultModelProvider);
        this.defaultModelId = text(defaultModelId);
    }

    public String recordDecision(SecurityEvent event, ProcessingResult result, ZeroTrustAction finalAction) {
        if (event == null) {
            return null;
        }
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return null;
        }

        Map<String, Object> metadata = event.getMetadata() == null ? Map.of() : event.getMetadata();
        String observationId = UUID.randomUUID().toString();
        String testRunId = testRunId(metadata);
        boolean protectable = isProtectable(metadata);
        Boolean llmDecisionPresent = firstBoolean(
                result != null ? result.getLlmDecisionPresent() : null,
                metadata.get("llmDecisionPresent"));
        boolean parserFailure = isParserFailure(result) || isParserFailure(metadata);
        boolean technicalFallback = (result != null && Boolean.TRUE.equals(result.getTechnicalFallbackApplied()))
                || Boolean.TRUE.equals(bool(metadata.get("technicalFallbackApplied")))
                || Boolean.TRUE.equals(bool(metadata.get("securityDecisionFallbackApplied")))
                || Boolean.TRUE.equals(bool(metadata.get("securityDecisionParsingFallbackApplied")))
                || Boolean.TRUE.equals(bool(metadata.get("syntheticSecurityDecisionApplied")))
                || Boolean.FALSE.equals(bool(metadata.get("rawExecutionSucceeded")));
        String failureReason = failureReason(result, metadata);
        String failureType = failureType(result, metadata, parserFailure, technicalFallback, failureReason, llmDecisionPresent, finalAction);
        String triggerSource = protectable ? "PROTECTABLE" : firstText(metadata, "triggerSource");
        if ("PENDING_REDLINE".equalsIgnoreCase(triggerSource)) {
            triggerSource = LEGACY_TRIGGER_SOURCE_NOT_APPLICABLE;
        }
        if (triggerSource == null) {
            triggerSource = LEGACY_TRIGGER_SOURCE_NOT_APPLICABLE;
        }
        String modelId = firstTextWithFallback(metadata, defaultModelId,
                "selectedModelId",
                "modelId",
                "runtimeModelId",
                "providerResponseModel",
                "requestedModelId",
                "preferredModel");
        String modelProvider = firstText(
                firstTextWithFallback(metadata, defaultModelProvider,
                        "selectedModelProvider",
                        "modelProvider",
                        "runtimeModelProvider",
                        "structuredOutputProviderFamily"),
                inferProviderFromModelId(modelId));
        if (isUnknown(modelProvider)) {
            modelProvider = firstText(defaultModelProvider, inferProviderFromModelId(modelId));
        }
        Map<String, Object> storedMetadata = metadataWithLatencyBreakdown(metadata, result, System.currentTimeMillis());
        Map<String, Object> latencyBreakdown = latencyBreakdownMetadata(storedMetadata);
        LocalDateTime now = LocalDateTime.now();
        String requestId = firstText(metadata, "requestId", "correlationId");
        String correlationId = firstText(firstText(metadata, "correlationId", "requestId"), requestId);
        String userId = firstText(event.getUserId(), text(metadata.get("userId")));
        String actorSessionKey = firstText(metadata, "actorSessionKey");
        String windowId = firstText(metadata, "windowId");

        long persistStart = System.currentTimeMillis();
        try {
            jdbcOperations.update("""
                    INSERT INTO ai_security_decision_observation (
                        observation_id,
                        event_id,
                        request_id,
                        correlation_id,
                        test_run_id,
                        user_id,
                        session_id,
                        context_binding_hash,
                        actor_session_key,
                        window_id,
                        trigger_source,
                        trigger_relation,
                        decision_boundary_mode,
                        http_method,
                        request_path,
                        resource_id,
                        model_provider,
                        model_id,
                        prompt_template_key,
                        final_action,
                        proposed_action,
                        llm_risk_score,
                        llm_confidence,
                        llm_latency_ms,
                        queue_wait_ms,
                        prompt_build_ms,
                        rag_vector_ms,
                        openai_call_ms,
                        parse_ms,
                        persist_ms,
                        total_analysis_ms,
                        llm_decision_present,
                        parser_failure,
                        technical_fallback,
                        timeout_failure,
                        model_unavailable,
                        failure_type,
                        fallback_category,
                        fallback_reason,
                        outcome_class,
                        metadata_json,
                        success,
                        created_at,
                        decided_at
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    observationId,
                    event.getEventId(),
                    requestId,
                    correlationId,
                    testRunId,
                    userId,
                    event.getSessionId(),
                    firstText(metadata, "contextBindingHash"),
                    actorSessionKey,
                    windowId,
                    triggerSource,
                    LEGACY_TRIGGER_RELATION_NOT_APPLICABLE,
                    firstText(metadata, "decisionBoundaryMode"),
                    firstText(metadata, "httpMethod", "method"),
                    firstText(metadata, "requestPath", "requestUri", "httpUri"),
                    firstText(metadata, "resourceId"),
                    modelProvider,
                    modelId,
                    firstText(metadata, "templateKey", "promptTemplateKey"),
                    finalAction != null ? finalAction.name() : text(result != null ? result.getAction() : null),
                    result != null ? result.getProposedAction() : null,
                    result != null ? result.resolveAuditRiskScore() : null,
                    result != null ? result.resolveAuditConfidence() : null,
                    result != null && result.getProcessingTimeMs() > 0 ? result.getProcessingTimeMs() : null,
                    longValue(latencyBreakdown.get("queueWaitMs")),
                    longValue(latencyBreakdown.get("promptBuildMs")),
                    longValue(latencyBreakdown.get("ragVectorMs")),
                    longValue(latencyBreakdown.get("openAiCallMs")),
                    longValue(latencyBreakdown.get("parseMs")),
                    longValue(latencyBreakdown.get("persistMs")),
                    longValue(latencyBreakdown.get("totalAnalysisMs")),
                    llmDecisionPresent,
                    parserFailure,
                    technicalFallback,
                    containsTimeout(failureReason) || "TIMEOUT".equals(failureType),
                    containsModelUnavailable(failureReason) || "MODEL_UNAVAILABLE".equals(failureType),
                    failureType,
                    result != null ? truncate(result.getTechnicalFallbackCategory(), 128) : null,
                    result != null ? summarize(SensitiveValueSanitizer.sanitizeText(result.getTechnicalFallbackReason()), 1024) : null,
                    LEGACY_OUTCOME_NOT_APPLICABLE,
                    writeJson(storedMetadata),
                    result != null && result.isSuccess() && failureType == null,
                    now,
                    now);

            long observationInsertMs = System.currentTimeMillis() - persistStart;
            log.info("[AiSecurityDecisionObservationWriter.timing] eventId={} observationId={} insertMs={} totalPersistMs={}",
                    event.getEventId(),
                    observationId,
                    observationInsertMs,
                    System.currentTimeMillis() - persistStart);
            return observationId;
        } catch (DataAccessException ex) {
            log.error("[AiSecurityDecisionObservationWriter] Failed to record AI security decision observation: eventId={}",
                    event.getEventId(), ex);
            return null;
        }
    }

    private Map<String, Object> metadataWithLatencyBreakdown(Map<String, Object> metadata, ProcessingResult result, long observationRecordedAtMs) {
        Map<String, Object> copy = new LinkedHashMap<>();
        if (metadata != null) {
            metadata.forEach((key, value) -> copy.put(key, SensitiveValueSanitizer.sanitizeValueForKey(key, value)));
        }
        copy.putIfAbsent("analysisObservationRecordedAt", observationRecordedAtMs);
        Long executionStartedAt = longValue(copy.get("analysisExecutionStartedAt"));
        if (executionStartedAt != null && result != null && result.getProcessingTimeMs() > 0) {
            copy.putIfAbsent("analysisExecutionFinishedAt", executionStartedAt + result.getProcessingTimeMs());
            copy.putIfAbsent("analysisCompletedAt", executionStartedAt + result.getProcessingTimeMs());
        } else {
            copy.putIfAbsent("analysisCompletedAt", observationRecordedAtMs);
        }
        Map<String, Object> latencyBreakdown = latencyBreakdown(copy, result);
        copy.put("latencyBreakdown", latencyBreakdown);
        latencyBreakdown.forEach((key, value) -> copy.put("latency" + Character.toUpperCase(key.charAt(0)) + key.substring(1), value));
        return copy;
    }


    @SuppressWarnings("unchecked")
    private Map<String, Object> latencyBreakdownMetadata(Map<String, Object> metadata) {
        Object value = metadata == null ? null : metadata.get("latencyBreakdown");
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> result = new LinkedHashMap<>();
            map.forEach((key, mapValue) -> result.put(String.valueOf(key), mapValue));
            return result;
        }
        return Map.of();
    }
    private Map<String, Object> latencyBreakdown(Map<String, Object> metadata, ProcessingResult result) {
        Map<String, Object> breakdown = new LinkedHashMap<>();
        Long monitorQueueWaitMs = durationBetween(metadata, "queuedAt", "dequeuedAt");
        Long stripeQueueWaitMs = durationBetween(metadata, "analysisQueuedAt", "analysisStartedAt");
        Long executorQueueWaitMs = durationBetween(metadata, "analysisSubmittedAt", "analysisExecutionStartedAt");
        breakdown.put("monitorQueueWaitMs", monitorQueueWaitMs);
        breakdown.put("stripeQueueWaitMs", stripeQueueWaitMs);
        breakdown.put("executorQueueWaitMs", executorQueueWaitMs);
        breakdown.put("queueWaitMs", sum(monitorQueueWaitMs, stripeQueueWaitMs, executorQueueWaitMs));
        breakdown.put("providerThrottleWaitMs", firstLong(metadata,
                "providerThrottleWaitMs",
                "layer1ProviderThrottleWaitMs",
                "layer2ProviderThrottleWaitMs"));
        breakdown.put("promptBuildMs", firstLong(metadata,
                "promptBuildLatencyMs",
                "promptCompositionMs",
                "promptViewCompositionMs",
                "promptRenderMs",
                "pipelinePromptGenerationMs"));
        breakdown.put("layerPreparationMs", firstLong(metadata,
                "layer1PromptPreparationMs",
                "promptBuildMs"));
        breakdown.put("ragVectorMs", firstLong(metadata,
                "ragVectorMs",
                "vectorSearchMs",
                "vectorLookupMs",
                "embeddingAcquireMs",
                "semanticEvidenceLookupMs",
                "contextRetrievalMs",
                "layer1RagSearchMs"));
        breakdown.put("openAiCallMs", firstLong(metadata,
                "openAiCallMs",
                "providerCallMs"));
        breakdown.put("providerCallTimeoutMs", firstLong(metadata,
                "providerCallTimeoutMs",
                "layer1ProviderCallTimeoutMs",
                "layer2ProviderCallTimeoutMs"));
        breakdown.put("parseMs", firstLong(metadata,
                "parseMs",
                "responseParseMs",
                "securityDecisionParseMs",
                "structuredOutputParseMs",
                "responseParsingMs",
                "responseExtractMs",
                "layer1ResponseValidateMs"));
        breakdown.put("persistMs", firstLong(metadata, "persistMs", "decisionPersistMs"));
        Long processingTimeMs = result == null ? null : result.getProcessingTimeMs();
        Long total = processingTimeMs != null && processingTimeMs > 0
                ? processingTimeMs
                : durationBetween(metadata, "analysisQueuedAt", "analysisCompletedAt");
        breakdown.put("totalAnalysisMs", total);
        return breakdown;
    }
    private Long sum(Long... values) {
        if (values == null) {
            return null;
        }
        long total = 0L;
        boolean present = false;
        for (Long value : values) {
            if (value != null) {
                total += value;
                present = true;
            }
        }
        return present ? total : null;
    }

    private Long durationBetween(Map<String, Object> metadata, String startKey, String endKey) {
        Long start = firstLong(metadata, startKey);
        Long end = firstLong(metadata, endKey);
        if (start == null || end == null || end < start) {
            return null;
        }
        return end - start;
    }

    private Long firstLong(Map<String, Object> metadata, String... keys) {
        if (metadata == null || keys == null) {
            return null;
        }
        for (String key : keys) {
            Long value = longValue(metadata.get(key));
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private Long longValue(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        String text = text(value);
        if (text == null) {
            return null;
        }
        try {
            return Long.parseLong(text);
        } catch (NumberFormatException ex) {
            try {
                return Math.round(Double.parseDouble(text));
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
    }
    private boolean isProtectable(Map<String, Object> metadata) {
        return Boolean.TRUE.equals(metadata.get("protectableDeclared"))
                || metadata.containsKey("protectableMethod");
    }

    private boolean isParserFailure(ProcessingResult result) {
        if (result == null) {
            return false;
        }
        return containsParserFailure(result.getTechnicalFallbackCategory())
                || containsParserFailure(result.getTechnicalFallbackReason());
    }

    private String failureType(
            ProcessingResult result,
            Map<String, Object> metadata,
            boolean parserFailure,
            boolean technicalFallback,
            String failureReason,
            Boolean llmDecisionPresent,
            ZeroTrustAction finalAction) {
        String structuredFailure = firstText(
                metadata,
                "structuredOutputFailureCategory",
                "securityDecisionParseFailureCategory",
                "decisionFailureCategory",
                "providerCallFailureCategory");
        if (containsBackpressure(structuredFailure) || containsBackpressure(failureReason)) {
            return "REJECTED_BACKPRESSURE";
        }
        if (containsProviderTimeout(structuredFailure) || containsProviderTimeout(failureReason)) {
            return "PROVIDER_CALL_TIMEOUT";
        }
        if (containsQueueTimeout(structuredFailure) || containsQueueTimeout(failureReason)) {
            return "QUEUE_TIMEOUT";
        }
        if (containsEventTimeout(structuredFailure) || containsEventTimeout(failureReason)) {
            return "EVENT_TIMEOUT";
        }
        if (containsTimeout(structuredFailure) || containsTimeout(failureReason)) {
            return "TIMEOUT";
        }
        if (containsProviderAuthenticationFailure(structuredFailure) || containsProviderAuthenticationFailure(failureReason)) {
            return "MODEL_UNAVAILABLE";
        }
        if (containsNoRuntimeLlmClient(failureReason)) {
            return "NO_RUNTIME_LLM_CLIENT";
        }
        if (containsNoPipelineExecutor(failureReason)) {
            return "NO_PIPELINE_EXECUTOR";
        }
        if (containsPromptContractViolation(failureReason)) {
            return "PROMPT_CONTRACT_VIOLATION";
        }
        if (containsMalformedJson(structuredFailure) || containsMalformedJson(failureReason)) {
            return "MALFORMED_JSON";
        }
        if (containsEmptyResponse(structuredFailure) || containsEmptyResponse(failureReason)) {
            return "EMPTY_RESPONSE";
        }
        if (parserFailure) {
            return "PARSER_FAILURE";
        }
        if (containsModelUnavailable(structuredFailure) || containsModelUnavailable(failureReason)) {
            return "MODEL_UNAVAILABLE";
        }
        if (containsLlmExecutionFailure(structuredFailure) || containsLlmExecutionFailure(failureReason)) {
            return "MODEL_UNAVAILABLE";
        }
        if (Boolean.FALSE.equals(llmDecisionPresent) && !isConcreteLlmDecision(finalAction)) {
            return "LLM_DECISION_MISSING";
        }
        if (technicalFallback) {
            return "TECHNICAL_FALLBACK";
        }
        if (result == null || !result.isSuccess()) {
            return "EXECUTION_FAILURE";
        }
        return null;
    }


    private boolean isConcreteLlmDecision(ZeroTrustAction finalAction) {
        return finalAction == ZeroTrustAction.ALLOW
                || finalAction == ZeroTrustAction.CHALLENGE
                || finalAction == ZeroTrustAction.BLOCK;
    }
    private String failureReason(ProcessingResult result, Map<String, Object> metadata) {
        return SensitiveValueSanitizer.sanitizeText(firstText(
                result != null ? result.getErrorMessage() : null,
                result != null ? result.getMessage() : null,
                result != null ? result.getTechnicalFallbackReason() : null,
                result != null ? result.getTechnicalFallbackCategory() : null,
                firstText(metadata, "securityDecisionRawExecutionFailureMessage"),
                firstText(metadata, "securityDecisionFallbackReason"),
                firstText(metadata, "decisionFailureMessage"),
                firstText(metadata, "structuredOutputFailureCategory"),
                firstText(metadata, "securityDecisionParseFailureCategory"),
                firstText(metadata, "providerCallFailureCategory")));
    }

    private boolean containsParserFailure(String value) {
        String normalized = normalize(value);
        return normalized != null && (normalized.contains("parser") || normalized.contains("parse"));
    }

    private boolean isParserFailure(Map<String, Object> metadata) {
        String category = firstText(
                metadata,
                "structuredOutputFailureCategory",
                "securityDecisionParseFailureCategory",
                "providerCallFailureCategory");
        String normalized = normalize(category);
        return normalized != null && !"none".equals(normalized)
                && (normalized.contains("json")
                || normalized.contains("parser")
                || normalized.contains("parse")
                || normalized.contains("missing_action")
                || normalized.contains("empty_response"));
    }

    private boolean containsBackpressure(String value) {
        String normalized = normalize(value);
        return normalized != null && (normalized.contains("rejected_backpressure")
                || normalized.contains("backpressure")
                || normalized.contains("queue rejected"));
    }
    private boolean containsProviderTimeout(String value) {
        String normalized = normalize(value);
        return normalized != null && (normalized.contains("provider_call_timeout")
                || normalized.contains("provider_timeout")
                || normalized.contains("provider call exceeded timeout")
                || normalized.contains("llm provider call exceeded timeout"));
    }

    private boolean containsQueueTimeout(String value) {
        String normalized = normalize(value);
        return normalized != null && (normalized.contains("queue_timeout")
                || normalized.contains("executor queue timeout")
                || normalized.contains("llm executor queue timeout"));
    }

    private boolean containsEventTimeout(String value) {
        String normalized = normalize(value);
        return normalized != null && (normalized.contains("event_timeout")
                || normalized.contains("event processing timeout")
                || normalized.contains("budget exceeded"));
    }

    private boolean containsTimeout(String value) {
        String normalized = normalize(value);
        return normalized != null && (normalized.contains("timeout") || normalized.contains("timed out"));
    }

    private boolean containsModelUnavailable(String value) {
        String normalized = normalize(value);
        return normalized != null && (normalized.contains("model unavailable")
                || normalized.contains("no runtime llm client")
                || normalized.contains("no pipeline executor")
                || normalized.contains("no model available"));
    }

    private boolean containsProviderAuthenticationFailure(String value) {
        String normalized = normalize(value);
        return normalized != null && (normalized.contains("invalid_api_key")
                || normalized.contains("incorrect api key")
                || normalized.contains("401 unauthorized")
                || normalized.contains("http 401")
                || normalized.contains("api key"));
    }

    private boolean containsLlmExecutionFailure(String value) {
        String normalized = normalize(value);
        return normalized != null && normalized.contains("llm_execution_failed");
    }

    private boolean containsNoRuntimeLlmClient(String value) {
        String normalized = normalize(value);
        return normalized != null && normalized.contains("no runtime llm client");
    }

    private boolean containsNoPipelineExecutor(String value) {
        String normalized = normalize(value);
        return normalized != null && normalized.contains("no pipeline executor");
    }

    private boolean containsPromptContractViolation(String value) {
        String normalized = normalize(value);
        return normalized != null && (normalized.contains("prompt contract")
                || normalized.contains("contract violation")
                || normalized.contains("decision contract"));
    }

    private boolean containsMalformedJson(String value) {
        String normalized = normalize(value);
        return normalized != null && (normalized.contains("malformed json")
                || normalized.contains("invalid json")
                || normalized.contains("json parse"));
    }

    private boolean containsEmptyResponse(String value) {
        String normalized = normalize(value);
        return normalized != null && (normalized.contains("empty response")
                || normalized.contains("blank response")
                || normalized.contains("empty llm response"));
    }

    private String normalize(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim().toLowerCase();
    }

    private JdbcOperations jdbcOperations() {
        return jdbcOperationsSupplier == null ? null : jdbcOperationsSupplier.get();
    }

    private String firstText(Map<String, Object> metadata, String... keys) {
        if (metadata == null || keys == null) {
            return null;
        }
        for (String key : keys) {
            String value = text(metadata.get(key));
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private String firstTextWithFallback(Map<String, Object> metadata, String fallback, String... keys) {
        return firstText(firstText(metadata, keys), fallback);
    }

    private String inferProviderFromModelId(String modelId) {
        String normalized = normalize(modelId);
        if (normalized == null) {
            return null;
        }
        if (normalized.startsWith("gpt-")
                || normalized.startsWith("o1")
                || normalized.startsWith("o3")
                || normalized.startsWith("o4")) {
            return "openai";
        }
        if (normalized.startsWith("claude-")) {
            return "anthropic";
        }
        if (normalized.contains("llama") || normalized.contains("mistral") || normalized.contains("qwen")) {
            return "ollama";
        }
        return null;
    }

    private boolean isUnknown(String value) {
        String normalized = normalize(value);
        return normalized == null || "unknown".equals(normalized) || "n/a".equals(normalized);
    }

    private String firstText(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            String text = text(value);
            if (text != null) {
                return text;
            }
        }
        return null;
    }

    private String testRunId(Map<String, Object> metadata) {
        String direct = firstText(metadata,
                "testRunId",
                "xContexaTestRunId");
        if (direct != null) {
            return direct;
        }
        Object rawSignals = firstObject(metadata, "rawSignalSnapshot", "rawSignalSnapshotJson", "rawSignalSnapshotMap");
        return testRunId(rawSignals);
    }

    @SuppressWarnings("unchecked")
    private String testRunId(Object rawSignals) {
        if (!(rawSignals instanceof Map<?, ?> map)) {
            return null;
        }
        Map<String, Object> typed = (Map<String, Object>) map;
        String direct = firstText(typed,
                "testRunId",
                "xContexaTestRunId");
        if (direct != null) {
            return direct;
        }
        Object ignored = typed.get("ignoredInputs");
        if (ignored instanceof Map<?, ?> ignoredMap) {
            for (Map.Entry<?, ?> entry : ignoredMap.entrySet()) {
                String key = entry.getKey() == null ? "" : entry.getKey().toString();
                if ("header.X-Contexa-Test-Run-Id".equalsIgnoreCase(key)
                        || "header.x-contexa-test-run-id".equalsIgnoreCase(key)
                        || key.toLowerCase().endsWith(".x-contexa-test-run-id")) {
                    return text(entry.getValue());
                }
            }
        }
        return null;
    }

    private Object firstObject(Map<String, Object> metadata, String... keys) {
        if (metadata == null || keys == null) {
            return null;
        }
        for (String key : keys) {
            if (metadata.containsKey(key) && metadata.get(key) != null) {
                return metadata.get(key);
            }
        }
        return null;
    }

    private String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isBlank() ? null : text;
    }

    private Boolean bool(Object... values) {
        if (values == null) {
            return null;
        }
        for (Object value : values) {
            if (value instanceof Boolean bool) {
                return bool;
            }
            String text = text(value);
            if (text != null) {
                return Boolean.parseBoolean(text);
            }
        }
        return null;
    }

    private Boolean firstBoolean(Object... values) {
        if (values == null) {
            return null;
        }
        for (Object value : values) {
            Boolean resolved = bool(value);
            if (resolved != null) {
                return resolved;
            }
        }
        return null;
    }

    private String writeJson(Object value) {
        if (value == null || objectMapper == null) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException ex) {
            return "{\"serializationError\":\"" + ex.getClass().getSimpleName() + "\"}";
        }
    }

    private String truncate(String value, int maxLength) {
        if (value == null || value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength);
    }

    private String summarize(String value, int maxLength) {
        String text = text(value);
        return text == null ? null : truncate(text.replaceAll("\\s+", " "), maxLength);
    }
}
