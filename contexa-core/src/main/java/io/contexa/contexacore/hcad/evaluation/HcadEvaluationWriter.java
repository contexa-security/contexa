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
        HcadDetectionEvaluation evaluation = HcadDetectionEvaluation.builder()
                .evaluationId(evaluationId)
                .requestId(report.requestId())
                .correlationId(report.requestId())
                .userId(report.userId())
                .contextBindingHash(report.contextBindingHash())
                .httpMethod(report.httpMethod())
                .requestPath(report.requestPath())
                .clientIp(report.clientIp())
                .mode(mode == null ? HcadPreTriggerMode.SHADOW.metadataValue() : mode.metadataValue())
                .earlyAnalysisScore(report.escalationScore())
                .band(report.escalationBand())
                .eligible(report.escalationEligible())
                .triggeredLlm(false)
                .duplicateSuppressed(false)
                .anchorSignals(writeJson(report.anchorSignals()))
                .corroboratingSignals(writeJson(report.corroboratingSignals()))
                .reasonCodes(writeJson(report.reasonCodes()))
                .signalSnapshotJson(writeJson(report.rawSignalSnapshot()))
                .signalProvenanceJson(writeJson(report.rawSignalSnapshot() == null
                        ? Map.of()
                        : report.rawSignalSnapshot().get("signalProvenance")))
                .outcomeClass("UNKNOWN")
                .createdAt(LocalDateTime.now())
                .build();
        save(evaluation);
        return evaluationId;
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
                     WHERE evaluation_id = ?
                    """, evaluationId);
            return;
        }
        HcadDetectionEvaluationRepository repository = repository();
        if (repository != null) {
            repository.findById(evaluationId).ifPresent(evaluation -> {
                evaluation.setDuplicateSuppressed(true);
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
                .httpMethod(firstText(metadata, "httpMethod", "protectableHttpMethod"))
                .requestPath(firstText(metadata, "requestPath", "requestUri", "httpUri"))
                .clientIp(event != null ? event.getSourceIp() : text(metadata.get("clientIp")))
                .mode(firstText(metadata, HcadPreProtectablePromotionAttributes.METADATA_MODE, "hcadMode"))
                .earlyAnalysisScore(integer(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE)))
                .band(text(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_BAND)))
                .eligible(bool(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_ELIGIBLE)))
                .triggeredLlm(false)
                .duplicateSuppressed(false)
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
                        http_method,
                        request_path,
                        client_ip,
                        mode,
                        early_analysis_score,
                        band,
                        eligible,
                        triggered_llm,
                        duplicate_suppressed,
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
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    evaluation.getEvaluationId(),
                    evaluation.getEventId(),
                    evaluation.getRequestId(),
                    evaluation.getCorrelationId(),
                    evaluation.getUserId(),
                    evaluation.getContextBindingHash(),
                    evaluation.getHttpMethod(),
                    evaluation.getRequestPath(),
                    evaluation.getClientIp(),
                    blankToDefault(evaluation.getMode(), "SHADOW"),
                    evaluation.getEarlyAnalysisScore(),
                    evaluation.getBand(),
                    evaluation.getEligible(),
                    boolDefault(evaluation.getTriggeredLlm(), false),
                    boolDefault(evaluation.getDuplicateSuppressed(), false),
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
