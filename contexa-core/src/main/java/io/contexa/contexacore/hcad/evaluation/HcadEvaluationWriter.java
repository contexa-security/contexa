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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.domain.entity.HcadDetectionEvaluation;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionAttributes;
import io.contexa.contexacore.hcad.trigger.HcadPreTriggerMode;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyEvidenceReport;
import io.contexa.contexacore.hcad.trigger.window.HcadObservationWindowLease;
import io.contexa.contexacore.repository.HcadDetectionEvaluationRepository;
import org.springframework.jdbc.core.JdbcOperations;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;

public class HcadEvaluationWriter {

    private final Supplier<HcadDetectionEvaluationRepository> repositorySupplier;
    private final Supplier<JdbcOperations> jdbcOperationsSupplier;
    private final ObjectMapper objectMapper;

    public HcadEvaluationWriter(
            HcadDetectionEvaluationRepository repository,
            ObjectMapper objectMapper) {
        this(() -> repository, () -> null, objectMapper);
    }

    public HcadEvaluationWriter(
            JdbcOperations jdbcOperations,
            ObjectMapper objectMapper) {
        this(() -> null, () -> jdbcOperations, objectMapper);
    }

    public HcadEvaluationWriter(
            Supplier<HcadDetectionEvaluationRepository> repositorySupplier,
            Supplier<JdbcOperations> jdbcOperationsSupplier,
            ObjectMapper objectMapper) {
        this.repositorySupplier = repositorySupplier == null ? () -> null : repositorySupplier;
        this.jdbcOperationsSupplier = jdbcOperationsSupplier == null ? () -> null : jdbcOperationsSupplier;
        this.objectMapper = objectMapper;
    }

    public String recordCandidate(HcadPreTriggerMode mode, PendingAnomalyEvidenceReport report) {
        if (report == null) {
            return null;
        }
        String evaluationId = UUID.randomUUID().toString();
        Map<String, Object> rawSnapshot = report.rawSignalSnapshot() == null ? Map.of() : report.rawSignalSnapshot();
        HcadDetectionEvaluation evaluation = HcadDetectionEvaluation.builder()
                .evaluationId(evaluationId)
                .requestId(report.requestId())
                .correlationId(report.requestId())
                .userId(report.userId())
                .contextBindingHash(report.contextBindingHash())
                .actorSessionKey(text(rawSnapshot.get("actorSessionKey")))
                .windowId(text(rawSnapshot.get("windowId")))
                .triggerScope(blankToDefault(text(rawSnapshot.get("triggerScope")), "SESSION_WINDOW"))
                .requestCount(integerDefault(rawSnapshot.get("requestCount"), 1))
                .httpMethod(report.httpMethod())
                .requestPath(report.requestPath())
                .clientIp(report.clientIp())
                .mode(mode == null ? HcadPreTriggerMode.SHADOW.metadataValue() : mode.metadataValue())
                .earlyAnalysisScore(report.escalationScore())
                .band(report.escalationBand())
                .eligible(report.escalationEligible())
                .triggeredLlm(false)
                .duplicateSuppressed(false)
                .duplicateSuppressedCount(integerDefault(rawSnapshot.get("duplicateSuppressedCount"), 0))
                .negativeCacheHit(false)
                .negativeCacheHitCount(integerDefault(rawSnapshot.get("negativeCacheHitCount"), 0))
                .resourceFamilies(writeJson(rawSnapshot.get("resourceFamilies")))
                .samplePaths(writeJson(rawSnapshot.get("samplePaths")))
                .anchorSignals(writeJson(report.anchorSignals()))
                .corroboratingSignals(writeJson(report.corroboratingSignals()))
                .reasonCodes(writeJson(report.reasonCodes()))
                .signalSnapshotJson(writeJson(rawSnapshot))
                .signalProvenanceJson(writeJson(rawSnapshot == null
                        ? Map.of()
                        : rawSnapshot.get("signalProvenance")))
                .outcomeClass("UNKNOWN")
                .createdAt(LocalDateTime.now())
                .build();
        save(evaluation);
        return evaluationId;
    }

    public void updateWindowObservation(String actorSessionKey, String windowId, HcadObservationWindowLease windowLease) {
        if (actorSessionKey == null || actorSessionKey.isBlank()
                || windowId == null || windowId.isBlank()
                || windowLease == null) {
            return;
        }
        int requestCount = Math.max(1, windowLease.requestCount());
        int duplicateSuppressedCount = Math.max(0, windowLease.duplicateSuppressedCount());
        String resourceFamilies = writeJson(windowLease.resourceFamilies());
        String samplePaths = writeJson(windowLease.samplePaths());
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations != null) {
            jdbcOperations.update("""
                    UPDATE hcad_detection_evaluation
                       SET request_count = GREATEST(COALESCE(request_count, 1), ?),
                           duplicate_suppressed_count = GREATEST(COALESCE(duplicate_suppressed_count, 0), ?),
                           resource_families = ?,
                           sample_paths = ?
                     WHERE actor_session_key = ?
                       AND window_id = ?
                    """,
                    requestCount,
                    duplicateSuppressedCount,
                    resourceFamilies,
                    samplePaths,
                    actorSessionKey,
                    windowId);
            return;
        }
        HcadDetectionEvaluationRepository repository = repository();
        if (repository != null) {
            for (HcadDetectionEvaluation evaluation : repository.findByActorSessionKeyAndWindowId(actorSessionKey, windowId)) {
                evaluation.setRequestCount(Math.max(
                        evaluation.getRequestCount() == null ? 1 : evaluation.getRequestCount(),
                        requestCount));
                evaluation.setDuplicateSuppressedCount(Math.max(
                        evaluation.getDuplicateSuppressedCount() == null ? 0 : evaluation.getDuplicateSuppressedCount(),
                        duplicateSuppressedCount));
                evaluation.setResourceFamilies(resourceFamilies);
                evaluation.setSamplePaths(samplePaths);
                repository.save(evaluation);
            }
        }
    }

    public void markTriggered(String evaluationId) {
        if (evaluationId == null || evaluationId.isBlank()) {
            return;
        }
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations != null) {
            jdbcOperations.update("""
                    UPDATE hcad_detection_evaluation
                       SET triggered_llm = true,
                           triggered_at = ?
                     WHERE evaluation_id = ?
                    """, LocalDateTime.now(), evaluationId);
            return;
        }
        HcadDetectionEvaluationRepository repository = repository();
        if (repository != null) {
            repository.findById(evaluationId).ifPresent(evaluation -> {
                evaluation.setTriggeredLlm(true);
                evaluation.setTriggeredAt(LocalDateTime.now());
                repository.save(evaluation);
            });
        }
    }

    public void markDuplicateSuppressed(String evaluationId) {
        if (evaluationId == null || evaluationId.isBlank()) {
            return;
        }
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations != null) {
            jdbcOperations.update("""
                    UPDATE hcad_detection_evaluation
                       SET duplicate_suppressed = true
                         , duplicate_suppressed_count = GREATEST(COALESCE(duplicate_suppressed_count, 0), 1)
                     WHERE evaluation_id = ?
                    """, evaluationId);
            return;
        }
        HcadDetectionEvaluationRepository repository = repository();
        if (repository != null) {
            repository.findById(evaluationId).ifPresent(evaluation -> {
                evaluation.setDuplicateSuppressed(true);
                evaluation.setDuplicateSuppressedCount(Math.max(
                        evaluation.getDuplicateSuppressedCount() == null ? 0 : evaluation.getDuplicateSuppressedCount(),
                        1));
                repository.save(evaluation);
            });
        }
    }

    public void markNegativeCacheHit(String evaluationId) {
        if (evaluationId == null || evaluationId.isBlank()) {
            return;
        }
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations != null) {
            jdbcOperations.update("""
                    UPDATE hcad_detection_evaluation
                       SET negative_cache_hit = true,
                           negative_cache_hit_count = GREATEST(COALESCE(negative_cache_hit_count, 0), 1)
                     WHERE evaluation_id = ?
                    """, evaluationId);
            return;
        }
        HcadDetectionEvaluationRepository repository = repository();
        if (repository != null) {
            repository.findById(evaluationId).ifPresent(evaluation -> {
                evaluation.setNegativeCacheHit(true);
                evaluation.setNegativeCacheHitCount(Math.max(
                        evaluation.getNegativeCacheHitCount() == null ? 0 : evaluation.getNegativeCacheHitCount(),
                        1));
                repository.save(evaluation);
            });
        }
    }

    public void markDecided(
            String evaluationId,
            String eventId,
            String llmAction,
            String llmProposedAction,
            Double llmRiskScore,
            Double llmConfidence,
            Long llmLatencyMs,
            String outcomeClass) {
        markDecided(
                evaluationId,
                eventId,
                llmAction,
                llmProposedAction,
                llmRiskScore,
                llmConfidence,
                llmLatencyMs,
                null,
                false,
                false,
                null,
                null,
                outcomeClass);
    }

    public void markDecided(
            String evaluationId,
            String eventId,
            String llmAction,
            String llmProposedAction,
            Double llmRiskScore,
            Double llmConfidence,
            Long llmLatencyMs,
            String llmReasoning,
            boolean llmParserFailure,
            boolean llmTechnicalFallback,
            String llmFallbackCategory,
            String llmFallbackReason,
            String outcomeClass) {
        if (evaluationId == null || evaluationId.isBlank()) {
            return;
        }
        String resolvedOutcomeClass = outcomeClass == null || outcomeClass.isBlank() ? "UNKNOWN" : outcomeClass;
        String reasoningSummary = summarize(llmReasoning, 1024);
        String reasoningHash = sha256(llmReasoning);
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations != null) {
            jdbcOperations.update("""
                    UPDATE hcad_detection_evaluation
                       SET event_id = COALESCE(NULLIF(?, ''), event_id),
                           llm_action = ?,
                           llm_proposed_action = ?,
                           llm_risk_score = ?,
                           llm_confidence = ?,
                           llm_latency_ms = ?,
                           llm_reasoning_summary = ?,
                           llm_reasoning_hash = ?,
                           llm_parser_failure = ?,
                           llm_technical_fallback = ?,
                           llm_fallback_category = ?,
                           llm_fallback_reason = ?,
                           outcome_class = ?,
                           decided_at = ?
                     WHERE evaluation_id = ?
                    """,
                    blankToEmpty(eventId),
                    llmAction,
                    llmProposedAction,
                    llmRiskScore,
                    llmConfidence,
                    llmLatencyMs,
                    reasoningSummary,
                    reasoningHash,
                    llmParserFailure,
                    llmTechnicalFallback,
                    truncate(llmFallbackCategory, 128),
                    summarize(llmFallbackReason, 1024),
                    resolvedOutcomeClass,
                    LocalDateTime.now(),
                    evaluationId);
            return;
        }
        HcadDetectionEvaluationRepository repository = repository();
        if (repository != null) {
            repository.findById(evaluationId).ifPresent(evaluation -> {
                if (eventId != null && !eventId.isBlank()) {
                    evaluation.setEventId(eventId);
                }
                evaluation.setLlmAction(llmAction);
                evaluation.setLlmProposedAction(llmProposedAction);
                evaluation.setLlmRiskScore(llmRiskScore);
                evaluation.setLlmConfidence(llmConfidence);
                evaluation.setLlmLatencyMs(llmLatencyMs);
                evaluation.setLlmReasoningSummary(reasoningSummary);
                evaluation.setLlmReasoningHash(reasoningHash);
                evaluation.setLlmParserFailure(llmParserFailure);
                evaluation.setLlmTechnicalFallback(llmTechnicalFallback);
                evaluation.setLlmFallbackCategory(truncate(llmFallbackCategory, 128));
                evaluation.setLlmFallbackReason(summarize(llmFallbackReason, 1024));
                evaluation.setOutcomeClass(resolvedOutcomeClass);
                evaluation.setDecidedAt(LocalDateTime.now());
                repository.save(evaluation);
            });
        }
    }

    public String recordObservedDecision(
            SecurityEvent event,
            String llmAction,
            String llmProposedAction,
            Double llmRiskScore,
            Double llmConfidence,
            Long llmLatencyMs,
            String outcomeClass) {
        return recordObservedDecision(
                event,
                llmAction,
                llmProposedAction,
                llmRiskScore,
                llmConfidence,
                llmLatencyMs,
                null,
                false,
                false,
                null,
                null,
                outcomeClass);
    }

    public String recordObservedDecision(
            SecurityEvent event,
            String llmAction,
            String llmProposedAction,
            Double llmRiskScore,
            Double llmConfidence,
            Long llmLatencyMs,
            String llmReasoning,
            boolean llmParserFailure,
            boolean llmTechnicalFallback,
            String llmFallbackCategory,
            String llmFallbackReason,
            String outcomeClass) {
        Map<String, Object> metadata = event != null && event.getMetadata() != null
                ? event.getMetadata()
                : Map.of();
        if (!isHcadPreTriggerEvaluationPresent(metadata)) {
            return null;
        }

        String evaluationId = UUID.randomUUID().toString();
        LocalDateTime now = LocalDateTime.now();
        HcadDetectionEvaluation evaluation = HcadDetectionEvaluation.builder()
                .evaluationId(evaluationId)
                .eventId(event != null ? event.getEventId() : null)
                .requestId(firstText(metadata, "requestId", "correlationId"))
                .correlationId(firstText(metadata, "correlationId", "requestId"))
                .userId(event != null ? event.getUserId() : firstText(metadata, "userId"))
                .contextBindingHash(text(metadata.get("contextBindingHash")))
                .actorSessionKey(text(metadata.get("actorSessionKey")))
                .windowId(text(metadata.get("windowId")))
                .triggerScope(blankToDefault(text(metadata.get("triggerScope")), "SESSION_WINDOW"))
                .requestCount(integerDefault(metadata.get("requestCount"), 1))
                .httpMethod(firstText(metadata, "httpMethod", "protectableHttpMethod"))
                .requestPath(firstText(metadata, "requestPath", "requestUri", "httpUri"))
                .clientIp(event != null ? event.getSourceIp() : text(metadata.get("clientIp")))
                .mode(firstText(metadata, HcadPreProtectablePromotionAttributes.METADATA_MODE, "hcadMode"))
                .earlyAnalysisScore(integer(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE)))
                .band(text(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_BAND)))
                .eligible(bool(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_ELIGIBLE)))
                .triggeredLlm(false)
                .duplicateSuppressed(false)
                .duplicateSuppressedCount(integerDefault(metadata.get("duplicateSuppressedCount"), 0))
                .negativeCacheHit(bool(metadata.get("negativeCacheHit")))
                .negativeCacheHitCount(integerDefault(metadata.get("negativeCacheHitCount"), 0))
                .resourceFamilies(writeJson(metadata.get("resourceFamilies")))
                .samplePaths(writeJson(metadata.get("samplePaths")))
                .anchorSignals(writeJson(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_ANCHOR_SIGNALS)))
                .corroboratingSignals(writeJson(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_CORROBORATING_SIGNALS)))
                .reasonCodes(writeJson(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_REASON_CODES)))
                .signalSnapshotJson(writeJson(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_RAW_SIGNALS)))
                .signalProvenanceJson(writeJson(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_PROVENANCE)))
                .llmAction(llmAction)
                .llmProposedAction(llmProposedAction)
                .llmRiskScore(llmRiskScore)
                .llmConfidence(llmConfidence)
                .llmLatencyMs(llmLatencyMs)
                .llmReasoningSummary(summarize(llmReasoning, 1024))
                .llmReasoningHash(sha256(llmReasoning))
                .llmParserFailure(llmParserFailure)
                .llmTechnicalFallback(llmTechnicalFallback)
                .llmFallbackCategory(truncate(llmFallbackCategory, 128))
                .llmFallbackReason(summarize(llmFallbackReason, 1024))
                .outcomeClass(outcomeClass == null || outcomeClass.isBlank() ? HcadOutcomeClassifier.UNKNOWN : outcomeClass)
                .createdAt(now)
                .decidedAt(now)
                .build();
        save(evaluation);
        return evaluationId;
    }

    private void save(HcadDetectionEvaluation evaluation) {
        if (evaluation == null) {
            return;
        }
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations != null) {
            jdbcOperations.update("""
                    INSERT INTO hcad_detection_evaluation (
                        evaluation_id,
                        event_id,
                        request_id,
                        correlation_id,
                        user_id,
                        context_binding_hash,
                        actor_session_key,
                        window_id,
                        trigger_scope,
                        request_count,
                        http_method,
                        request_path,
                        client_ip,
                        mode,
                        early_analysis_score,
                        band,
                        eligible,
                        triggered_llm,
                        duplicate_suppressed,
                        duplicate_suppressed_count,
                        negative_cache_hit,
                        negative_cache_hit_count,
                        resource_families,
                        sample_paths,
                        anchor_signals,
                        corroborating_signals,
                        reason_codes,
                        signal_snapshot_json,
                        signal_provenance_json,
                        llm_action,
                        llm_proposed_action,
                        llm_risk_score,
                        llm_confidence,
                        llm_latency_ms,
                        llm_reasoning_summary,
                        llm_reasoning_hash,
                        llm_parser_failure,
                        llm_technical_fallback,
                        llm_fallback_category,
                        llm_fallback_reason,
                        outcome_class,
                        created_at,
                        triggered_at,
                        decided_at
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    evaluation.getEvaluationId(),
                    evaluation.getEventId(),
                    evaluation.getRequestId(),
                    evaluation.getCorrelationId(),
                    evaluation.getUserId(),
                    evaluation.getContextBindingHash(),
                    evaluation.getActorSessionKey(),
                    evaluation.getWindowId(),
                    blankToDefault(evaluation.getTriggerScope(), "SESSION_WINDOW"),
                    evaluation.getRequestCount() == null ? 1 : evaluation.getRequestCount(),
                    evaluation.getHttpMethod(),
                    evaluation.getRequestPath(),
                    evaluation.getClientIp(),
                    blankToDefault(evaluation.getMode(), "SHADOW"),
                    evaluation.getEarlyAnalysisScore(),
                    evaluation.getBand(),
                    evaluation.getEligible(),
                    boolDefault(evaluation.getTriggeredLlm(), false),
                    boolDefault(evaluation.getDuplicateSuppressed(), false),
                    evaluation.getDuplicateSuppressedCount() == null ? 0 : evaluation.getDuplicateSuppressedCount(),
                    boolDefault(evaluation.getNegativeCacheHit(), false),
                    evaluation.getNegativeCacheHitCount() == null ? 0 : evaluation.getNegativeCacheHitCount(),
                    evaluation.getResourceFamilies(),
                    evaluation.getSamplePaths(),
                    evaluation.getAnchorSignals(),
                    evaluation.getCorroboratingSignals(),
                    evaluation.getReasonCodes(),
                    evaluation.getSignalSnapshotJson(),
                    evaluation.getSignalProvenanceJson(),
                    evaluation.getLlmAction(),
                    evaluation.getLlmProposedAction(),
                    evaluation.getLlmRiskScore(),
                    evaluation.getLlmConfidence(),
                    evaluation.getLlmLatencyMs(),
                    evaluation.getLlmReasoningSummary(),
                    evaluation.getLlmReasoningHash(),
                    boolDefault(evaluation.getLlmParserFailure(), false),
                    boolDefault(evaluation.getLlmTechnicalFallback(), false),
                    evaluation.getLlmFallbackCategory(),
                    evaluation.getLlmFallbackReason(),
                    blankToDefault(evaluation.getOutcomeClass(), "UNKNOWN"),
                    evaluation.getCreatedAt() == null ? LocalDateTime.now() : evaluation.getCreatedAt(),
                    evaluation.getTriggeredAt(),
                    evaluation.getDecidedAt());
            return;
        }
        HcadDetectionEvaluationRepository repository = repository();
        if (repository != null) {
            repository.save(evaluation);
        }
    }

    private HcadDetectionEvaluationRepository repository() {
        return repositorySupplier == null ? null : repositorySupplier.get();
    }

    private JdbcOperations jdbcOperations() {
        return jdbcOperationsSupplier == null ? null : jdbcOperationsSupplier.get();
    }

    private boolean isHcadPreTriggerEvaluationPresent(Map<String, Object> metadata) {
        return Boolean.TRUE.equals(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_EVALUATED))
                || metadata.containsKey(HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE)
                || metadata.containsKey(HcadPreProtectablePromotionAttributes.METADATA_SCORE);
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

    private String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isBlank() ? null : text;
    }

    private Integer integer(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        String text = text(value);
        if (text == null) {
            return null;
        }
        try {
            return Integer.parseInt(text);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private Integer integerDefault(Object value, int defaultValue) {
        Integer resolved = integer(value);
        return resolved == null ? defaultValue : resolved;
    }

    private Boolean bool(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        String text = text(value);
        return text == null ? null : Boolean.parseBoolean(text);
    }

    private Boolean boolDefault(Boolean value, boolean defaultValue) {
        return value == null ? defaultValue : value;
    }

    private String blankToDefault(String value, String defaultValue) {
        return value == null || value.isBlank() ? defaultValue : value;
    }

    private String blankToEmpty(String value) {
        return value == null || value.isBlank() ? "" : value;
    }

    private String writeJson(Object value) {
        if (value == null) {
            return "null";
        }
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException ex) {
            return "{\"serializationError\":\"" + sanitize(ex.getClass().getSimpleName()) + "\"}";
        }
    }

    private String sanitize(String value) {
        return value == null ? "" : value.replace("\"", "");
    }

    private String summarize(String value, int maxLength) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return truncate(value.trim(), maxLength);
    }

    private String truncate(String value, int maxLength) {
        if (value == null) {
            return null;
        }
        String text = value.trim();
        if (maxLength <= 0 || text.length() <= maxLength) {
            return text;
        }
        return text.substring(0, maxLength);
    }

    private String sha256(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                builder.append(String.format("%02x", b));
            }
            return builder.toString();
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
    }
}
