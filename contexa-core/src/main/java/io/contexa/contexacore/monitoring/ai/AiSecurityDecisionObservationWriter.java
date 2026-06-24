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
import io.contexa.contexacore.hcad.semantic.HcadSemanticEvidenceRefreshService;
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
    private final String defaultModelProvider;
    private final String defaultModelId;
    private final HcadSemanticEvidenceRefreshService semanticEvidenceRefreshService;

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
        this(jdbcOperationsSupplier, objectMapper, defaultModelProvider, defaultModelId, null);
    }

    public AiSecurityDecisionObservationWriter(
            Supplier<JdbcOperations> jdbcOperationsSupplier,
            ObjectMapper objectMapper,
            String defaultModelProvider,
            String defaultModelId,
            HcadSemanticEvidenceRefreshService semanticEvidenceRefreshService) {
        this.jdbcOperationsSupplier = jdbcOperationsSupplier == null ? () -> null : jdbcOperationsSupplier;
        this.objectMapper = objectMapper;
        this.defaultModelProvider = text(defaultModelProvider);
        this.defaultModelId = text(defaultModelId);
        this.semanticEvidenceRefreshService = semanticEvidenceRefreshService;
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
        String testRunId = testRunId(metadata);
        boolean hcadTriggered = isHcadTriggered(metadata);
        boolean hcadObserved = isHcadObserved(metadata, hcadEvaluationId);
        boolean protectable = isProtectable(metadata);
        Boolean hcadEligible = firstBoolean(
                hcadEligible(metadata),
                durableHcadEligible(jdbcOperations, hcadEvaluationId));
        if (!hcadTriggered && protectable && hcadObserved && Boolean.TRUE.equals(hcadEligible)) {
            hcadTriggered = true;
        }
        if (!protectable && hcadTriggered && hcadObserved
                && isProtectableMergePending(jdbcOperations, hcadEvaluationId)) {
            protectable = true;
        }
        if (protectable && hcadObserved) {
            markProtectableObserved(
                    jdbcOperations,
                    hcadEvaluationId,
                    firstText(metadata, "resourceId", "protectableResourceId", "requestedResourceId", "protectedResourceId"),
                    firstText(metadata, "protectableResourceUrl", "requestPath", "requestUri", "httpUri"),
                    firstText(metadata, "protectableHttpMethod", "httpMethod", "method"));
        }
        Boolean llmDecisionPresent = firstBoolean(
                result != null ? result.getLlmDecisionPresent() : null,
                metadata.get("llmDecisionPresent"));
        boolean parserFailure = isParserFailure(result) || isParserFailure(metadata);
        boolean technicalFallback = (result != null && Boolean.TRUE.equals(result.getTechnicalFallbackApplied()))
                || Boolean.TRUE.equals(bool(metadata.get("technicalFallbackApplied")));
        String failureReason = failureReason(result, metadata);
        String failureType = failureType(result, metadata, parserFailure, technicalFallback, failureReason, llmDecisionPresent);
        String triggerSource = triggerSource(metadata, hcadTriggered, hcadObserved, protectable);
        String triggerRelation = triggerRelation(hcadTriggered, hcadObserved, protectable);
        String outcomeClass = outcomeClass(result, finalAction, hcadTriggered, hcadObserved, failureType);
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
        LocalDateTime now = LocalDateTime.now();

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
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    observationId,
                    event.getEventId(),
                    firstText(metadata, "requestId", "correlationId"),
                    firstText(metadata, "correlationId", "requestId"),
                    testRunId,
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
                    hcadEligible,
                    firstText(metadata, "httpMethod", "protectableHttpMethod", "method"),
                    firstText(metadata, "requestPath", "requestUri", "httpUri", "protectableResourceUrl"),
                    firstText(metadata, "resourceId", "protectableResourceId", "requestedResourceId", "protectedResourceId"),
                    modelProvider,
                    modelId,
                    firstText(metadata, "templateKey", "promptTemplateKey"),
                    finalAction != null ? finalAction.name() : text(result != null ? result.getAction() : null),
                    result != null ? result.getProposedAction() : null,
                    result != null ? result.resolveAuditRiskScore() : null,
                    result != null ? result.resolveAuditConfidence() : null,
                    result != null && result.getProcessingTimeMs() > 0 ? result.getProcessingTimeMs() : null,
                    llmDecisionPresent,
                    parserFailure,
                    technicalFallback,
                    containsTimeout(failureReason) || "TIMEOUT".equals(failureType),
                    containsModelUnavailable(failureReason) || "MODEL_UNAVAILABLE".equals(failureType),
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
                    hcadEligible,
                    result,
                    finalAction,
                    testRunId,
                    now);
            refreshSemanticEvidence(event, metadata, result, finalAction, failureType);
            return observationId;
        } catch (DataAccessException ex) {
            log.error("[AiSecurityDecisionObservationWriter] Failed to record AI security decision observation: eventId={}",
                    event.getEventId(), ex);
            return null;
        }
    }

    private void refreshSemanticEvidence(
            SecurityEvent event,
            Map<String, Object> metadata,
            ProcessingResult result,
            ZeroTrustAction finalAction,
            String failureType) {
        if (semanticEvidenceRefreshService == null || !semanticEvidenceMaterial(result, finalAction, failureType)) {
            return;
        }
        try {
            semanticEvidenceRefreshService.refreshAfterDecision(event, metadata);
        } catch (RuntimeException ex) {
            log.debug("[AiSecurityDecisionObservationWriter] Failed to refresh HCAD semantic evidence: eventId={}",
                    event != null ? event.getEventId() : null, ex);
        }
    }

    private boolean semanticEvidenceMaterial(
            ProcessingResult result,
            ZeroTrustAction finalAction,
            String failureType) {
        if (failureType != null || result == null || !result.isSuccess()) {
            return false;
        }
        return semanticEvidenceAction(finalAction != null ? finalAction.name() : null)
                || semanticEvidenceAction(result.getProposedAction())
                || semanticEvidenceAction(result.getAction());
    }

    private boolean semanticEvidenceAction(String action) {
        String normalized = normalize(action);
        return "allow".equals(normalized);
    }

    public boolean markProtectableMerged(
            String hcadEvaluationId,
            String resourceId,
            String resourceUrl,
            String httpMethod) {
        if (hcadEvaluationId == null || hcadEvaluationId.isBlank()) {
            return false;
        }
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return false;
        }
        boolean hcadMarked = jdbcOperations.update("""
                UPDATE hcad_detection_evaluation
                   SET protectable_observed = true,
                       protectable_resource_id = COALESCE(NULLIF(protectable_resource_id, ''), NULLIF(?, '')),
                       protectable_resource_url = COALESCE(NULLIF(protectable_resource_url, ''), NULLIF(?, ''), request_path),
                       protectable_http_method = COALESCE(NULLIF(protectable_http_method, ''), NULLIF(?, ''), http_method)
                 WHERE evaluation_id = ?
                """,
                blankToEmpty(resourceId),
                blankToEmpty(resourceUrl),
                blankToEmpty(httpMethod),
                hcadEvaluationId) > 0;
        int observations = jdbcOperations.update("""
                UPDATE ai_security_decision_observation
                   SET trigger_relation = 'HCAD_AND_PROTECTABLE',
                       resource_id = COALESCE(NULLIF(resource_id, ''), NULLIF(?, '')),
                       request_path = COALESCE(NULLIF(request_path, ''), NULLIF(?, ''), request_path),
                       http_method = COALESCE(NULLIF(http_method, ''), NULLIF(?, ''), http_method)
                 WHERE hcad_evaluation_id = ?
                   AND trigger_relation = 'HCAD_ONLY'
                """,
                blankToEmpty(resourceId),
                blankToEmpty(resourceUrl),
                blankToEmpty(httpMethod),
                hcadEvaluationId);
        jdbcOperations.update("""
                UPDATE hcad_llm_decision_correlation
                   SET trigger_relation = 'HCAD_AND_PROTECTABLE'
                 WHERE hcad_evaluation_id = ?
                   AND trigger_relation = 'HCAD_ONLY'
                """,
                hcadEvaluationId);
        return hcadMarked || observations > 0;
    }

    private boolean markProtectableObserved(
            JdbcOperations jdbcOperations,
            String hcadEvaluationId,
            String resourceId,
            String resourceUrl,
            String httpMethod) {
        if (jdbcOperations == null || hcadEvaluationId == null || hcadEvaluationId.isBlank()) {
            return false;
        }
        try {
            return jdbcOperations.update("""
                    UPDATE hcad_detection_evaluation
                       SET protectable_observed = true,
                           protectable_resource_id = COALESCE(NULLIF(protectable_resource_id, ''), NULLIF(?, '')),
                           protectable_resource_url = COALESCE(NULLIF(protectable_resource_url, ''), NULLIF(?, ''), request_path),
                           protectable_http_method = COALESCE(NULLIF(protectable_http_method, ''), NULLIF(?, ''), http_method)
                     WHERE evaluation_id = ?
                    """,
                    blankToEmpty(resourceId),
                    blankToEmpty(resourceUrl),
                    blankToEmpty(httpMethod),
                    hcadEvaluationId) > 0;
        } catch (DataAccessException ex) {
            log.warn("[AiSecurityDecisionObservationWriter] Failed to mark protectable observation: hcadEvaluationId={}",
                    hcadEvaluationId, ex);
            return false;
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
            Boolean hcadEligible,
            ProcessingResult result,
            ZeroTrustAction finalAction,
            String testRunId,
            LocalDateTime now) {
        jdbcOperations.update("""
                INSERT INTO hcad_llm_decision_correlation (
                    correlation_id,
                    hcad_evaluation_id,
                    llm_observation_id,
                    event_id,
                    request_id,
                    test_run_id,
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
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                UUID.randomUUID().toString(),
                hcadEvaluationId,
                observationId,
                event.getEventId(),
                firstText(metadata, "requestId", "correlationId"),
                testRunId,
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
                hcadEligible,
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

    private boolean isProtectableMergePending(JdbcOperations jdbcOperations, String hcadEvaluationId) {
        if (jdbcOperations == null || hcadEvaluationId == null || hcadEvaluationId.isBlank()) {
            return false;
        }
        try {
            Boolean pending = jdbcOperations.queryForObject("""
                    SELECT COALESCE(protectable_observed, false)
                      FROM hcad_detection_evaluation
                     WHERE evaluation_id = ?
                    """, Boolean.class, hcadEvaluationId);
            return Boolean.TRUE.equals(pending);
        } catch (DataAccessException ex) {
            return false;
        }
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

    private Boolean hcadEligible(Map<String, Object> metadata) {
        return bool(
                metadata.get(HcadPreProtectablePromotionAttributes.METADATA_ELIGIBLE),
                metadata.get("hcadEscalationEligible"));
    }

    private Boolean durableHcadEligible(JdbcOperations jdbcOperations, String hcadEvaluationId) {
        if (jdbcOperations == null || hcadEvaluationId == null || hcadEvaluationId.isBlank()) {
            return null;
        }
        try {
            return jdbcOperations.queryForObject("""
                    SELECT COALESCE(eligible, false)
                            OR trigger_decision_reason = 'PROTECTABLE_LLM_REUSED'
                      FROM hcad_detection_evaluation
                     WHERE evaluation_id = ?
                    """, Boolean.class, hcadEvaluationId);
        } catch (DataAccessException ex) {
            return null;
        }
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
                || containsParserFailure(result.getTechnicalFallbackReason());
    }

    private String failureType(
            ProcessingResult result,
            Map<String, Object> metadata,
            boolean parserFailure,
            boolean technicalFallback,
            String failureReason,
            Boolean llmDecisionPresent) {
        String structuredFailure = firstText(
                metadata,
                "structuredOutputFailureCategory",
                "securityDecisionParseFailureCategory",
                "decisionFailureCategory");
        if (containsTimeout(structuredFailure) || containsTimeout(failureReason)) {
            return "TIMEOUT";
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
        if (Boolean.FALSE.equals(llmDecisionPresent)) {
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

    private String failureReason(ProcessingResult result, Map<String, Object> metadata) {
        return firstText(
                result != null ? result.getErrorMessage() : null,
                result != null ? result.getMessage() : null,
                result != null ? result.getTechnicalFallbackReason() : null,
                result != null ? result.getTechnicalFallbackCategory() : null,
                firstText(metadata, "securityDecisionRawExecutionFailureMessage"),
                firstText(metadata, "securityDecisionFallbackReason"),
                firstText(metadata, "decisionFailureMessage"),
                firstText(metadata, "structuredOutputFailureCategory"),
                firstText(metadata, "securityDecisionParseFailureCategory"));
    }

    private boolean containsParserFailure(String value) {
        String normalized = normalize(value);
        return normalized != null && (normalized.contains("parser") || normalized.contains("parse"));
    }

    private boolean isParserFailure(Map<String, Object> metadata) {
        String category = firstText(
                metadata,
                "structuredOutputFailureCategory",
                "securityDecisionParseFailureCategory");
        String normalized = normalize(category);
        return normalized != null && !"none".equals(normalized)
                && (normalized.contains("json")
                || normalized.contains("parser")
                || normalized.contains("parse")
                || normalized.contains("missing_action")
                || normalized.contains("empty_response"));
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
                "hcadTestRunId",
                "hcadExtremeRunId",
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
                "hcadTestRunId",
                "hcadExtremeRunId",
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

    private String blankToEmpty(String value) {
        return value == null || value.isBlank() ? "" : value;
    }

    private String summarize(String value, int maxLength) {
        String text = text(value);
        return text == null ? null : truncate(text.replaceAll("\\s+", " "), maxLength);
    }
}
