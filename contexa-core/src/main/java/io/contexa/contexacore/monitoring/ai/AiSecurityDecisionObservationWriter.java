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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.hcad.evaluation.HcadOutcomeClassifier;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionAttributes;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcOperations;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;

@Slf4j
public class AiSecurityDecisionObservationWriter {

    private final Supplier<JdbcOperations> jdbcOperationsSupplier;
    private final ObjectMapper objectMapper;

    public AiSecurityDecisionObservationWriter(
            Supplier<JdbcOperations> jdbcOperationsSupplier,
            ObjectMapper objectMapper) {
        this.jdbcOperationsSupplier = jdbcOperationsSupplier == null ? () -> null : jdbcOperationsSupplier;
        this.objectMapper = objectMapper;
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
        String hcadEvaluationId = firstText(metadata, "hcadEvaluationId");
        boolean hcadTriggered = isHcadTriggered(metadata);
        boolean hcadObserved = isHcadObserved(metadata, hcadEvaluationId);
        boolean protectable = isProtectable(metadata);
        boolean parserFailure = isParserFailure(result);
        boolean technicalFallback = result != null && Boolean.TRUE.equals(result.getTechnicalFallbackApplied());
        String failureReason = failureReason(result);
        String failureType = failureType(result, parserFailure, technicalFallback, failureReason);
        String triggerSource = triggerSource(metadata, hcadTriggered, hcadObserved, protectable);
        String triggerRelation = triggerRelation(hcadTriggered, hcadObserved, protectable);
        String outcomeClass = outcomeClass(result, finalAction, hcadTriggered, hcadObserved, failureType);
        LocalDateTime now = LocalDateTime.now();

        try {
            jdbcOperations.update("""
                    INSERT INTO ai_security_decision_observation (
                        observation_id,
                        event_id,
                        request_id,
                        correlation_id,
                        user_id,
                        session_id,
                        context_binding_hash,
                        actor_session_key,
                        window_id,
                        hcad_evaluation_id,
                        trigger_source,
                        trigger_relation,
                        decision_boundary_mode,
                        hcad_mode,
                        hcad_score,
                        hcad_band,
                        hcad_eligible,
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
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    observationId,
                    event.getEventId(),
                    firstText(metadata, "requestId", "correlationId"),
                    firstText(metadata, "correlationId", "requestId"),
                    firstText(event.getUserId(), text(metadata.get("userId"))),
                    event.getSessionId(),
                    firstText(metadata, "contextBindingHash"),
                    firstText(metadata, "actorSessionKey"),
                    firstText(metadata, "windowId"),
                    hcadEvaluationId,
                    triggerSource,
                    triggerRelation,
                    firstText(metadata, "decisionBoundaryMode"),
                    firstText(metadata, "hcadMode", HcadPreProtectablePromotionAttributes.METADATA_MODE),
                    integer(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE),
                            metadata.get(HcadPreProtectablePromotionAttributes.METADATA_SCORE),
                            metadata.get("earlyAnalysisScore"),
                            metadata.get("hcadEscalationScore")),
                    firstText(metadata, HcadPreProtectablePromotionAttributes.METADATA_BAND, "hcadBand", "hcadEscalationBand"),
                    bool(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_ELIGIBLE),
                            metadata.get("hcadEscalationEligible")),
                    firstText(metadata, "httpMethod", "protectableHttpMethod", "method"),
                    firstText(metadata, "requestPath", "requestUri", "httpUri", "protectableResourceUrl"),
                    firstText(metadata, "resourceId", "protectableResourceId", "requestedResourceId", "protectedResourceId"),
                    firstText(metadata, "selectedModelProvider", "modelProvider"),
                    firstText(metadata, "selectedModelId", "modelId", "requestedModelId", "preferredModel"),
                    firstText(metadata, "templateKey", "promptTemplateKey"),
                    finalAction != null ? finalAction.name() : text(result != null ? result.getAction() : null),
                    result != null ? result.getProposedAction() : null,
                    result != null ? result.resolveAuditRiskScore() : null,
                    result != null ? result.resolveAuditConfidence() : null,
                    result != null && result.getProcessingTimeMs() > 0 ? result.getProcessingTimeMs() : null,
                    result != null ? result.getLlmDecisionPresent() : null,
                    parserFailure,
                    technicalFallback,
                    containsTimeout(failureReason),
                    containsModelUnavailable(failureReason),
                    failureType,
                    result != null ? truncate(result.getTechnicalFallbackCategory(), 128) : null,
                    result != null ? summarize(result.getTechnicalFallbackReason(), 1024) : null,
                    outcomeClass,
                    writeJson(metadata),
                    result != null && result.isSuccess(),
                    now,
                    now);

            recordCorrelation(
                    jdbcOperations,
                    observationId,
                    event,
                    metadata,
                    hcadEvaluationId,
                    triggerRelation,
                    outcomeClass,
                    result,
                    finalAction,
                    now);
            return observationId;
        } catch (DataAccessException ex) {
            log.error("[AiSecurityDecisionObservationWriter] Failed to record AI security decision observation: eventId={}",
                    event.getEventId(), ex);
            return null;
        }
    }

    private void recordCorrelation(
            JdbcOperations jdbcOperations,
            String observationId,
            SecurityEvent event,
            Map<String, Object> metadata,
            String hcadEvaluationId,
            String triggerRelation,
            String outcomeClass,
            ProcessingResult result,
            ZeroTrustAction finalAction,
            LocalDateTime now) {
        jdbcOperations.update("""
                INSERT INTO hcad_llm_decision_correlation (
                    correlation_id,
                    hcad_evaluation_id,
                    llm_observation_id,
                    event_id,
                    request_id,
                    user_id,
                    actor_session_key,
                    window_id,
                    trigger_relation,
                    outcome_class,
                    hcad_score,
                    hcad_band,
                    hcad_eligible,
                    llm_final_action,
                    llm_proposed_action,
                    llm_risk_score,
                    llm_confidence,
                    created_at,
                    decided_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                UUID.randomUUID().toString(),
                hcadEvaluationId,
                observationId,
                event.getEventId(),
                firstText(metadata, "requestId", "correlationId"),
                firstText(event.getUserId(), text(metadata.get("userId"))),
                firstText(metadata, "actorSessionKey"),
                firstText(metadata, "windowId"),
                triggerRelation,
                outcomeClass,
                integer(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE),
                        metadata.get(HcadPreProtectablePromotionAttributes.METADATA_SCORE),
                        metadata.get("earlyAnalysisScore"),
                        metadata.get("hcadEscalationScore")),
                firstText(metadata, HcadPreProtectablePromotionAttributes.METADATA_BAND, "hcadBand", "hcadEscalationBand"),
                bool(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_ELIGIBLE),
                        metadata.get("hcadEscalationEligible")),
                finalAction != null ? finalAction.name() : text(result != null ? result.getAction() : null),
                result != null ? result.getProposedAction() : null,
                result != null ? result.resolveAuditRiskScore() : null,
                result != null ? result.resolveAuditConfidence() : null,
                now,
                now);
    }

    private String triggerSource(
            Map<String, Object> metadata,
            boolean hcadTriggered,
            boolean hcadObserved,
            boolean protectable) {
        String explicit = firstText(metadata, "triggerSource");
        if (explicit != null) {
            return explicit;
        }
        if (hcadTriggered) {
            return "HCAD_PRE_TRIGGER";
        }
        if (protectable) {
            return "PROTECTABLE";
        }
        return hcadObserved ? "HCAD_OBSERVED" : "UNKNOWN";
    }

    private String triggerRelation(boolean hcadTriggered, boolean hcadObserved, boolean protectable) {
        if (hcadTriggered && protectable) {
            return "HCAD_AND_PROTECTABLE";
        }
        if (hcadTriggered) {
            return "HCAD_ONLY";
        }
        if (protectable) {
            return "PROTECTABLE_ONLY";
        }
        if (hcadObserved) {
            return "OBSERVED_ONLY";
        }
        return "UNMATCHED_LLM";
    }

    private String outcomeClass(
            ProcessingResult result,
            ZeroTrustAction finalAction,
            boolean hcadTriggered,
            boolean hcadObserved,
            String failureType) {
        if (failureType != null) {
            return HcadOutcomeClassifier.UNKNOWN;
        }
        if (hcadTriggered) {
            return HcadOutcomeClassifier.classifyHcadTriggered(result, finalAction);
        }
        if (hcadObserved) {
            return HcadOutcomeClassifier.classifyHcadObservation(result, finalAction);
        }
        return "UNOBSERVED";
    }

    private boolean isHcadTriggered(Map<String, Object> metadata) {
        String triggerSource = firstText(metadata, "triggerSource");
        return "HCAD_PRE_TRIGGER".equalsIgnoreCase(triggerSource)
                || "PENDING_REDLINE".equalsIgnoreCase(triggerSource);
    }

    private boolean isHcadObserved(Map<String, Object> metadata, String hcadEvaluationId) {
        return hcadEvaluationId != null
                || Boolean.TRUE.equals(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_EVALUATED))
                || metadata.containsKey(HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE)
                || metadata.containsKey(HcadPreProtectablePromotionAttributes.METADATA_SCORE);
    }

    private boolean isProtectable(Map<String, Object> metadata) {
        return Boolean.TRUE.equals(metadata.get("protectableDeclared"))
                || metadata.containsKey("protectableResourceId")
                || metadata.containsKey("protectableResourceUrl")
                || metadata.containsKey("protectableMethod");
    }

    private boolean isParserFailure(ProcessingResult result) {
        if (result == null) {
            return false;
        }
        return containsParserFailure(result.getTechnicalFallbackCategory())
                || containsParserFailure(result.getTechnicalFallbackReason())
                || (Boolean.FALSE.equals(result.getLlmDecisionPresent())
                        && Boolean.TRUE.equals(result.getTechnicalFallbackApplied()));
    }

    private String failureType(
            ProcessingResult result,
            boolean parserFailure,
            boolean technicalFallback,
            String failureReason) {
        if (containsNoRuntimeLlmClient(failureReason)) {
            return "NO_RUNTIME_LLM_CLIENT";
        }
        if (containsNoPipelineExecutor(failureReason)) {
            return "NO_PIPELINE_EXECUTOR";
        }
        if (containsPromptContractViolation(failureReason)) {
            return "PROMPT_CONTRACT_VIOLATION";
        }
        if (containsMalformedJson(failureReason)) {
            return "MALFORMED_JSON";
        }
        if (containsEmptyResponse(failureReason)) {
            return "EMPTY_RESPONSE";
        }
        if (parserFailure) {
            return "PARSER_FAILURE";
        }
        if (containsTimeout(failureReason)) {
            return "TIMEOUT";
        }
        if (containsModelUnavailable(failureReason)) {
            return "MODEL_UNAVAILABLE";
        }
        if (technicalFallback) {
            return "TECHNICAL_FALLBACK";
        }
        if (result == null || !result.isSuccess()) {
            return "EXECUTION_FAILURE";
        }
        return null;
    }

    private String failureReason(ProcessingResult result) {
        if (result == null) {
            return null;
        }
        return firstText(
                result.getErrorMessage(),
                result.getMessage(),
                result.getTechnicalFallbackReason(),
                result.getTechnicalFallbackCategory());
    }

    private boolean containsParserFailure(String value) {
        String normalized = normalize(value);
        return normalized != null && (normalized.contains("parser") || normalized.contains("parse"));
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

    private String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isBlank() ? null : text;
    }

    private Integer integer(Object... values) {
        if (values == null) {
            return null;
        }
        for (Object value : values) {
            if (value instanceof Number number) {
                return number.intValue();
            }
            String text = text(value);
            if (text == null) {
                continue;
            }
            try {
                return Integer.parseInt(text);
            } catch (NumberFormatException ignored) {
                // Try the next value.
            }
        }
        return null;
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
