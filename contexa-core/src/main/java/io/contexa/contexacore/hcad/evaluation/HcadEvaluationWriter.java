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
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionSignal;
import io.contexa.contexacore.hcad.projection.HcadBaselineComparison;
import io.contexa.contexacore.hcad.projection.HcadFieldProvenance;
import io.contexa.contexacore.hcad.projection.HcadPromptSecurityContextFieldContract;
import io.contexa.contexacore.hcad.projection.HcadPromptSecurityContextFieldRegistry;
import io.contexa.contexacore.hcad.projection.HcadTrustedSource;
import io.contexa.contexacore.hcad.trigger.HcadPreTriggerMode;
import io.contexa.contexacore.hcad.trigger.HcadRequestPathUtils;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyEvidenceReport;
import io.contexa.contexacore.hcad.trigger.window.HcadObservationWindowLease;
import io.contexa.contexacore.repository.HcadDetectionEvaluationRepository;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.transaction.support.TransactionOperations;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;

public class HcadEvaluationWriter {

    private final Supplier<HcadDetectionEvaluationRepository> repositorySupplier;
    private final Supplier<JdbcOperations> jdbcOperationsSupplier;
    private final Supplier<TransactionOperations> transactionOperationsSupplier;
    private final ObjectMapper objectMapper;
    private final ThreadLocal<Boolean> writeTransactionActive = ThreadLocal.withInitial(() -> false);

    public HcadEvaluationWriter(
            HcadDetectionEvaluationRepository repository,
            ObjectMapper objectMapper) {
        this(() -> repository, () -> null, () -> null, objectMapper);
    }

    public HcadEvaluationWriter(
            JdbcOperations jdbcOperations,
            ObjectMapper objectMapper) {
        this(() -> null, () -> jdbcOperations, () -> null, objectMapper);
    }

    public HcadEvaluationWriter(
            Supplier<HcadDetectionEvaluationRepository> repositorySupplier,
            Supplier<JdbcOperations> jdbcOperationsSupplier,
            ObjectMapper objectMapper) {
        this(repositorySupplier, jdbcOperationsSupplier, () -> null, objectMapper);
    }

    public HcadEvaluationWriter(
            Supplier<HcadDetectionEvaluationRepository> repositorySupplier,
            Supplier<JdbcOperations> jdbcOperationsSupplier,
            Supplier<TransactionOperations> transactionOperationsSupplier,
            ObjectMapper objectMapper) {
        this.repositorySupplier = repositorySupplier == null ? () -> null : repositorySupplier;
        this.jdbcOperationsSupplier = jdbcOperationsSupplier == null ? () -> null : jdbcOperationsSupplier;
        this.transactionOperationsSupplier = transactionOperationsSupplier == null ? () -> null : transactionOperationsSupplier;
        this.objectMapper = objectMapper;
    }

    public String recordCandidate(HcadPreTriggerMode mode, PendingAnomalyEvidenceReport report) {
        if (!isWriteTransactionActive()) {
            return inWriteTransaction(() -> recordCandidate(mode, report));
        }
        if (report == null) {
            return null;
        }
        String evaluationId = UUID.randomUUID().toString();
        String evaluationEventId = "hcad-" + evaluationId;
        HcadDetectionEvaluation evaluation = buildEvaluation(
                mode,
                report,
                evaluationId,
                evaluationEventId,
                null);
        save(evaluation);
        return evaluationId;
    }

    private HcadDetectionEvaluation buildEvaluation(
            HcadPreTriggerMode mode,
            PendingAnomalyEvidenceReport report,
            String evaluationId,
            String evaluationEventId,
            String triggerDecisionReasonOverride) {
        Map<String, Object> rawSnapshot = report.rawSignalSnapshot() == null
                ? new LinkedHashMap<>()
                : new LinkedHashMap<>(report.rawSignalSnapshot());
        String requestId = firstNonBlank(
                report.requestId(),
                text(rawSnapshot.get("requestId")),
                text(rawSnapshot.get("correlationId")),
                evaluationEventId);
        rawSnapshot.putIfAbsent("requestId", requestId);
        rawSnapshot.putIfAbsent("correlationId", requestId);
        String normalizedPath = HcadRequestPathUtils.normalizePathText(report.requestPath());
        String resourceId = resolveResourceId(rawSnapshot, normalizedPath);
        HcadBaselineComparison baselineComparison = baselineComparison(rawSnapshot);
        List<String> evidenceGaps = evidenceGapCodes(report, baselineComparison);
        String nonTriggerReason = report.shouldTrigger() ? null : nonTriggerReason(report, baselineComparison, evidenceGaps);
        String triggerDecisionReason = triggerDecisionReasonOverride != null
                ? triggerDecisionReasonOverride
                : report.shouldTrigger() ? "TRIGGER_CANDIDATE" : nonTriggerReason;
        HcadDetectionEvaluation evaluation = HcadDetectionEvaluation.builder()
                .evaluationId(evaluationId)
                .eventId(evaluationEventId)
                .requestId(requestId)
                .correlationId(requestId)
                .testRunId(testRunId(rawSnapshot))
                .userId(report.userId())
                .contextBindingHash(report.contextBindingHash())
                .actorSessionKey(text(rawSnapshot.get("actorSessionKey")))
                .windowId(text(rawSnapshot.get("windowId")))
                .triggerScope(blankToDefault(text(rawSnapshot.get("triggerScope")), "SESSION_WINDOW"))
                .requestCount(integerDefault(rawSnapshot.get("requestCount"), 1))
                .httpMethod(report.httpMethod())
                .requestPath(report.requestPath())
                .normalizedPath(normalizedPath)
                .resourceId(resourceId)
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
                .protectableObserved(boolDefault(bool(rawSnapshot.get("protectableObserved")), false))
                .protectableResourceId(null)
                .protectableResourceUrl(null)
                .protectableHttpMethod(null)
                .resourceFamilies(writeJson(rawSnapshot.get("resourceFamilies")))
                .samplePaths(writeJson(rawSnapshot.get("samplePaths")))
                .anchorSignals(writeJson(report.anchorSignals()))
                .corroboratingSignals(writeJson(report.corroboratingSignals()))
                .reasonCodes(writeJson(report.reasonCodes()))
                .nonTriggerReason(nonTriggerReason)
                .evidenceGapCodes(writeJson(evidenceGaps))
                .baselineAvailable(baselineComparison.available())
                .baselineEstablished(baselineComparison.established())
                .baselineUpdateCount(baselineComparison.updateCount())
                .baselineMinSamples(baselineComparison.minSamples())
                .baselineComparedDimensions(baselineComparison.comparedDimensions())
                .baselineMismatchCount(baselineComparison.mismatchCount())
                .baselineMatchRatio(baselineComparison.matchRatio())
                .baselineMismatchedDimensions(writeJson(baselineComparison.mismatchedDimensions()))
                .baselineCurrentValuesJson(writeJson(baselineComparison.currentValues()))
                .baselineReferenceValuesJson(writeJson(baselineComparison.baselineValues()))
                .triggerDecisionReason(triggerDecisionReason)
                .signalSnapshotJson(writeJson(rawSnapshot))
                .signalProvenanceJson(writeJson(rawSnapshot == null
                        ? Map.of()
                        : rawSnapshot.get("signalProvenance")))
                .scoreBreakdownJson(writeJson(scoreBreakdown(report, rawSnapshot)))
                .signalExplanationsJson(writeJson(signalExplanations(report, rawSnapshot, baselineComparison)))
                .contextExplanationJson(writeJson(contextExplanation(report, rawSnapshot, normalizedPath, resourceId, requestId)))
                .baselineExplanationJson(writeJson(baselineExplanation(baselineComparison)))
                .semanticEvidenceExplanationJson(writeJson(semanticEvidenceExplanation(rawSnapshot)))
                .freshnessExplanationJson(writeJson(freshnessExplanation(rawSnapshot, baselineComparison)))
                .triggerExplanationJson(writeJson(triggerExplanation(report, nonTriggerReason, triggerDecisionReason, evidenceGaps)))
                .outcomeClass("UNKNOWN")
                .createdAt(LocalDateTime.now())
                .build();
        return evaluation;
    }

    public void updateWindowObservation(String actorSessionKey, String windowId, HcadObservationWindowLease windowLease) {
        if (!isWriteTransactionActive()) {
            inWriteTransaction(() -> updateWindowObservation(actorSessionKey, windowId, windowLease));
            return;
        }
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
        if (!isWriteTransactionActive()) {
            inWriteTransaction(() -> markTriggered(evaluationId));
            return;
        }
        if (evaluationId == null || evaluationId.isBlank()) {
            return;
        }
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations != null) {
            jdbcOperations.update("""
                    UPDATE hcad_detection_evaluation
                       SET triggered_llm = true,
                           non_trigger_reason = NULL,
                           trigger_decision_reason = 'TRIGGER_PUBLISHED',
                           trigger_explanation_json = ?,
                           triggered_at = ?
                     WHERE evaluation_id = ?
                    """,
                    writeJson(triggerStateExplanation("TRIGGER_PUBLISHED", null, true, null, null, null, null)),
                    LocalDateTime.now(),
                    evaluationId);
            return;
        }
        HcadDetectionEvaluationRepository repository = repository();
        if (repository != null) {
            repository.findById(evaluationId).ifPresent(evaluation -> {
                evaluation.setTriggeredLlm(true);
                evaluation.setNonTriggerReason(null);
                evaluation.setTriggerDecisionReason("TRIGGER_PUBLISHED");
                evaluation.setTriggerExplanationJson(writeJson(triggerStateExplanation(
                        "TRIGGER_PUBLISHED",
                        null,
                        true,
                        null,
                        null,
                        null,
                        null)));
                evaluation.setTriggeredAt(LocalDateTime.now());
                repository.save(evaluation);
            });
        }
    }

    public void markDuplicateSuppressed(String evaluationId) {
        if (!isWriteTransactionActive()) {
            inWriteTransaction(() -> markDuplicateSuppressed(evaluationId));
            return;
        }
        if (evaluationId == null || evaluationId.isBlank()) {
            return;
        }
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations != null) {
            jdbcOperations.update("""
                    UPDATE hcad_detection_evaluation
                       SET duplicate_suppressed = true
                         , duplicate_suppressed_count = GREATEST(COALESCE(duplicate_suppressed_count, 0), 1)
                         , non_trigger_reason = COALESCE(non_trigger_reason, 'DUPLICATE_SUPPRESSED')
                         , trigger_decision_reason = 'DUPLICATE_SUPPRESSED'
                         , trigger_explanation_json = ?
                     WHERE evaluation_id = ?
                    """,
                    writeJson(duplicateSuppressedExplanation(evaluationId, "DUPLICATE_SUPPRESSED")),
                    evaluationId);
            return;
        }
        HcadDetectionEvaluationRepository repository = repository();
        if (repository != null) {
            repository.findById(evaluationId).ifPresent(evaluation -> {
                evaluation.setDuplicateSuppressed(true);
                evaluation.setDuplicateSuppressedCount(Math.max(
                        evaluation.getDuplicateSuppressedCount() == null ? 0 : evaluation.getDuplicateSuppressedCount(),
                        1));
                if (evaluation.getNonTriggerReason() == null || evaluation.getNonTriggerReason().isBlank()) {
                    evaluation.setNonTriggerReason("DUPLICATE_SUPPRESSED");
                }
                evaluation.setTriggerDecisionReason("DUPLICATE_SUPPRESSED");
                evaluation.setTriggerExplanationJson(writeJson(duplicateSuppressedExplanation(
                        evaluationId,
                        evaluation.getNonTriggerReason())));
                repository.save(evaluation);
            });
        }
    }

    public void markTriggerSuppressed(String evaluationId, String reason) {
        if (!isWriteTransactionActive()) {
            inWriteTransaction(() -> markTriggerSuppressed(evaluationId, reason));
            return;
        }
        if (evaluationId == null || evaluationId.isBlank()) {
            return;
        }
        String resolvedReason = truncate(blankToDefault(reason, "TRIGGER_SUPPRESSED"), 128);
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations != null) {
            jdbcOperations.update("""
                    UPDATE hcad_detection_evaluation
                       SET triggered_llm = false,
                           non_trigger_reason = COALESCE(non_trigger_reason, ?),
                           trigger_decision_reason = ?,
                           trigger_explanation_json = ?
                     WHERE evaluation_id = ?
                    """,
                    resolvedReason,
                    resolvedReason,
                    writeJson(triggerStateExplanation(resolvedReason, resolvedReason, false, null, null, null, null)),
                    evaluationId);
            return;
        }
        HcadDetectionEvaluationRepository repository = repository();
        if (repository != null) {
            repository.findById(evaluationId).ifPresent(evaluation -> {
                evaluation.setTriggeredLlm(false);
                if (evaluation.getNonTriggerReason() == null || evaluation.getNonTriggerReason().isBlank()) {
                    evaluation.setNonTriggerReason(resolvedReason);
                }
                evaluation.setTriggerDecisionReason(resolvedReason);
                evaluation.setTriggerExplanationJson(writeJson(triggerStateExplanation(
                        resolvedReason,
                        evaluation.getNonTriggerReason(),
                        false,
                        null,
                        null,
                        null,
                        null)));
                repository.save(evaluation);
            });
        }
    }

    public void markProtectableObserved(
            String evaluationId,
            String resourceId,
            String resourceUrl,
            String httpMethod,
            boolean protectableLlmReused) {
        if (!isWriteTransactionActive()) {
            inWriteTransaction(() -> markProtectableObserved(
                    evaluationId,
                    resourceId,
                    resourceUrl,
                    httpMethod,
                    protectableLlmReused));
            return;
        }
        if (evaluationId == null || evaluationId.isBlank()) {
            return;
        }
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations != null) {
            if (protectableLlmReused) {
                jdbcOperations.update("""
                        UPDATE hcad_detection_evaluation
                           SET protectable_observed = true,
                               protectable_resource_id = COALESCE(NULLIF(protectable_resource_id, ''), NULLIF(?, '')),
                               protectable_resource_url = COALESCE(NULLIF(protectable_resource_url, ''), NULLIF(?, ''), request_path),
                               protectable_http_method = COALESCE(NULLIF(protectable_http_method, ''), NULLIF(?, ''), http_method),
                               triggered_llm = true,
                               non_trigger_reason = NULL,
                               trigger_decision_reason = 'PROTECTABLE_LLM_REUSED',
                               trigger_explanation_json = ?,
                               triggered_at = COALESCE(triggered_at, ?)
                         WHERE evaluation_id = ?
                        """,
                        blankToEmpty(resourceId),
                        blankToEmpty(resourceUrl),
                        blankToEmpty(httpMethod),
                        writeJson(triggerStateExplanation(
                                "PROTECTABLE_LLM_REUSED",
                                null,
                                true,
                                "HCAD_AND_PROTECTABLE",
                                resourceId,
                                resourceUrl,
                                httpMethod)),
                        LocalDateTime.now(),
                        evaluationId);
                return;
            }
            jdbcOperations.update("""
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
                    evaluationId);
        }
    }

    public void markNegativeCacheHit(String evaluationId) {
        if (!isWriteTransactionActive()) {
            inWriteTransaction(() -> markNegativeCacheHit(evaluationId));
            return;
        }
        if (evaluationId == null || evaluationId.isBlank()) {
            return;
        }
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations != null) {
            jdbcOperations.update("""
                    UPDATE hcad_detection_evaluation
                       SET negative_cache_hit = true,
                           negative_cache_hit_count = GREATEST(COALESCE(negative_cache_hit_count, 0), 1),
                           non_trigger_reason = COALESCE(non_trigger_reason, 'NEGATIVE_CACHE_HIT'),
                           trigger_decision_reason = 'NEGATIVE_CACHE_HIT'
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
                if (evaluation.getNonTriggerReason() == null || evaluation.getNonTriggerReason().isBlank()) {
                    evaluation.setNonTriggerReason("NEGATIVE_CACHE_HIT");
                }
                evaluation.setTriggerDecisionReason("NEGATIVE_CACHE_HIT");
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
        if (!isWriteTransactionActive()) {
            inWriteTransaction(() -> markDecided(
                    evaluationId,
                    eventId,
                    llmAction,
                    llmProposedAction,
                    llmRiskScore,
                    llmConfidence,
                    llmLatencyMs,
                    llmReasoning,
                    llmParserFailure,
                    llmTechnicalFallback,
                    llmFallbackCategory,
                    llmFallbackReason,
                    outcomeClass));
            return;
        }
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
        if (!isWriteTransactionActive()) {
            return inWriteTransaction(() -> recordObservedDecision(
                    event,
                    llmAction,
                    llmProposedAction,
                    llmRiskScore,
                    llmConfidence,
                    llmLatencyMs,
                    llmReasoning,
                    llmParserFailure,
                    llmTechnicalFallback,
                    llmFallbackCategory,
                    llmFallbackReason,
                    outcomeClass));
        }
        PendingAnomalyEvidenceReport report = observedReport(event);
        if (report == null) {
            return null;
        }
        Map<String, Object> metadata = event.getMetadata();
        HcadPreTriggerMode mode;
        try {
            mode = HcadPreTriggerMode.from(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_MODE));
        } catch (RuntimeException ignored) {
            mode = HcadPreTriggerMode.SHADOW;
        }
        String evaluationId = UUID.randomUUID().toString();
        HcadDetectionEvaluation evaluation = buildEvaluation(
                mode,
                report,
                evaluationId,
                firstNonBlank(event.getEventId(), "hcad-" + evaluationId),
                "OBSERVED_WITH_LLM_DECISION");
        evaluation.setLlmAction(llmAction);
        evaluation.setLlmProposedAction(llmProposedAction);
        evaluation.setLlmRiskScore(llmRiskScore);
        evaluation.setLlmConfidence(llmConfidence);
        evaluation.setLlmLatencyMs(llmLatencyMs);
        evaluation.setLlmReasoningSummary(summarize(llmReasoning, 1024));
        evaluation.setLlmReasoningHash(sha256(llmReasoning));
        evaluation.setLlmParserFailure(llmParserFailure);
        evaluation.setLlmTechnicalFallback(llmTechnicalFallback);
        evaluation.setLlmFallbackCategory(truncate(llmFallbackCategory, 128));
        evaluation.setLlmFallbackReason(summarize(llmFallbackReason, 1024));
        evaluation.setOutcomeClass(blankToDefault(outcomeClass, "UNKNOWN"));
        evaluation.setDecidedAt(LocalDateTime.now());
        save(evaluation);
        return evaluationId;
    }

    private PendingAnomalyEvidenceReport observedReport(SecurityEvent event) {
        if (event == null || event.getMetadata() == null
                || !isHcadPreTriggerEvaluationPresent(event.getMetadata())) {
            return null;
        }
        Map<String, Object> metadata = event.getMetadata();
        Map<String, Object> rawSnapshot = rawSnapshotMap(
                metadata.get(HcadPreProtectablePromotionAttributes.METADATA_RAW_SIGNALS));
        rawSnapshot.put("protectableObserved", true);
        Object score = metadata.get(HcadPreProtectablePromotionAttributes.METADATA_EARLY_ANALYSIS_SCORE);
        if (score == null) {
            score = metadata.get(HcadPreProtectablePromotionAttributes.METADATA_SCORE);
        }
        return PendingAnomalyEvidenceReport.noTrigger(
                event.getUserId(),
                firstText(metadata, "contextBindingHash"),
                firstText(metadata, "triggerStateKey"),
                firstNonBlank(firstText(metadata, "requestId", "correlationId"), event.getEventId()),
                event.getSessionId(),
                firstText(metadata, "requestPath", "resourceUrl", "resourceId"),
                firstText(metadata, "httpMethod", "method"),
                event.getSourceIp(),
                integerDefault(score, 0),
                blankToDefault(firstText(
                        metadata,
                        HcadPreProtectablePromotionAttributes.METADATA_BAND), "LOW"),
                boolDefault(bool(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_ELIGIBLE)), false),
                blankToDefault(firstText(
                        metadata,
                        HcadPreProtectablePromotionAttributes.METADATA_VERSION), "hcad-promotion-v1"),
                stringList(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_ANCHOR_SIGNALS)),
                stringList(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_CORROBORATING_SIGNALS)),
                stringList(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_REASON_CODES)),
                firstText(metadata, HcadPreProtectablePromotionAttributes.METADATA_SUMMARY),
                rawSnapshot);
    }
    private Map<String, Object> scoreBreakdown(
            PendingAnomalyEvidenceReport report,
            Map<String, Object> rawSnapshot) {
        Map<String, Object> breakdown = new LinkedHashMap<>();
        breakdown.put("structuredScore", integer(rawSnapshot == null ? null : rawSnapshot.get("structuredScore")));
        breakdown.put("semanticEvidenceScore", integer(rawSnapshot == null ? null : rawSnapshot.get("semanticEvidenceScore")));
        breakdown.put("normalSuppressionScore", integer(rawSnapshot == null ? null : rawSnapshot.get("semanticNormalSuppressionScore")));
        breakdown.put("semanticEvidenceScoreApplied", integer(rawSnapshot == null ? null : rawSnapshot.get("semanticEvidenceScoreApplied")));
        breakdown.put("finalScore", report == null ? null : report.escalationScore());
        breakdown.put("band", report == null ? null : report.escalationBand());
        breakdown.put("eligible", report == null ? null : report.escalationEligible());
        breakdown.put("thresholds", rawSnapshot == null ? null : rawSnapshot.get("scoringThresholds"));
        breakdown.put("eligibleQuorum", rawSnapshot == null ? null : rawSnapshot.get("eligibleQuorum"));
        breakdown.put("eligibleFalseReasons", rawSnapshot == null ? List.of() : rawSnapshot.get("eligibleFalseReasons"));
        breakdown.put("scoreFormula", rawSnapshot == null ? null : rawSnapshot.get("scoreFormula"));
        breakdown.put("scoreInterpretation", scoreInterpretation(report, rawSnapshot));
        return breakdown;
    }

    private Map<String, Object> scoreInterpretation(
            PendingAnomalyEvidenceReport report,
            Map<String, Object> rawSnapshot) {
        Map<String, Object> interpretation = new LinkedHashMap<>();
        int score = report == null
                ? integerDefault(rawSnapshot == null ? null : rawSnapshot.get("earlyAnalysisScore"), 0)
                : report.escalationScore();
        interpretation.put("score", score);
        interpretation.put("band", report == null ? null : report.escalationBand());
        interpretation.put("eligible", report == null ? null : report.escalationEligible());
        if (score == 0) {
            interpretation.put("summary", "No trusted risk signal contributed to the early-detection score.");
            interpretation.put("reason", zeroScoreReason(report, rawSnapshot));
        } else {
            interpretation.put("summary", "Score is the bounded sum of structured evidence and semantic evidence minus normal-similarity suppression.");
            interpretation.put("reason", report == null ? null : report.reasonSummary());
        }
        return interpretation;
    }

    private String zeroScoreReason(PendingAnomalyEvidenceReport report, Map<String, Object> rawSnapshot) {
        if (rawSnapshot != null && Boolean.TRUE.equals(rawSnapshot.get("nonActionableRequest"))) {
            return "NON_ACTIONABLE_REQUEST_EXCLUDED";
        }
        if (report != null && isEmpty(report.anchorSignals()) && isEmpty(report.corroboratingSignals())) {
            return "NO_APPLIED_TRUSTED_RISK_SIGNAL";
        }
        Object semantic = rawSnapshot == null ? null : rawSnapshot.get("semanticEvidence");
        if (semantic instanceof Map<?, ?> map && map.containsKey("semanticEvidenceGapCodes")) {
            return "SEMANTIC_EVIDENCE_GAP";
        }
        return "CONDITIONS_NOT_MET";
    }

    private List<Map<String, Object>> signalExplanations(
            PendingAnomalyEvidenceReport report,
            Map<String, Object> rawSnapshot,
            HcadBaselineComparison baselineComparison) {
        List<String> anchors = report == null ? List.of() : report.anchorSignals();
        List<String> corroborating = report == null ? List.of() : report.corroboratingSignals();
        Object scorerExplanations = rawSnapshot == null ? null : rawSnapshot.get("signalExplanations");
        if (scorerExplanations instanceof List<?> scorerList && !scorerList.isEmpty()) {
            return normalizeSignalExplanations(scorerList, rawSnapshot, baselineComparison);
        }
        List<Map<String, Object>> explanations = new ArrayList<>();
        for (HcadPreProtectablePromotionSignal signal : HcadPreProtectablePromotionSignal.values()) {
            boolean appliedAsAnchor = anchors.contains(signal.name());
            boolean appliedAsCorroborating = corroborating.contains(signal.name());
            Map<String, Object> explanation = new LinkedHashMap<>();
            explanation.put("signal", signal.name());
            explanation.put("displayName", signalDisplayName(signal));
            explanation.put("type", signal.isAnchor() ? "ANCHOR" : "CORROBORATING");
            explanation.put("weight", signal.weight());
            explanation.put("requiredFields", signal.requiredContractFields());
            explanation.put("condition", signalCondition(signal));
            explanation.put("applied", appliedAsAnchor || appliedAsCorroborating);
            explanation.put("appliedAs", appliedAsAnchor ? "ANCHOR" : appliedAsCorroborating ? "CORROBORATING" : null);
            explanation.put("currentValues", valuesForFields(rawSnapshot, signal.requiredContractFields()));
            explanation.put("baselineValues", baselineValuesForSignal(signal, baselineComparison));
            explanation.put("fieldSources", fieldExplanations(rawSnapshot, signal.requiredContractFields()));
            explanation.put("excludedReason", appliedAsAnchor || appliedAsCorroborating
                    ? null
                    : signalUnmetReason(signal, rawSnapshot));
            explanation.put("unmetReason", appliedAsAnchor || appliedAsCorroborating
                    ? null
                    : signalUnmetReason(signal, rawSnapshot));
            explanations.add(explanation);
        }
        return explanations;
    }

    private List<Map<String, Object>> normalizeSignalExplanations(
            List<?> scorerList,
            Map<String, Object> rawSnapshot,
            HcadBaselineComparison baselineComparison) {
        List<Map<String, Object>> explanations = new ArrayList<>();
        for (Object item : scorerList) {
            if (item instanceof Map<?, ?> map) {
                Map<String, Object> explanation = new LinkedHashMap<>();
                map.forEach((key, value) -> explanation.put(String.valueOf(key), value));
                HcadPreProtectablePromotionSignal signal = signal(text(explanation.get("signal")));
                if (signal != null) {
                    explanation.putIfAbsent("displayName", signalDisplayName(signal));
                    explanation.putIfAbsent("type", signal.isAnchor() ? "ANCHOR" : "CORROBORATING");
                    explanation.putIfAbsent("baselineValues", baselineValuesForSignal(signal, baselineComparison));
                    explanation.put("fieldSources", fieldExplanations(rawSnapshot, signal.requiredContractFields()));
                    explanation.putIfAbsent("excludedReason", explanation.get("unmetReason"));
                }
                explanations.add(explanation);
            }
        }
        return explanations;
    }

    private HcadPreProtectablePromotionSignal signal(String signalName) {
        if (signalName == null || signalName.isBlank()) {
            return null;
        }
        try {
            return HcadPreProtectablePromotionSignal.valueOf(signalName);
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    private String signalDisplayName(HcadPreProtectablePromotionSignal signal) {
        return switch (signal) {
            case IMPOSSIBLE_TRAVEL -> "Unusual access location";
            case FAILED_LOGIN_BURST -> "Repeated failed login";
            case AUTH_CONTEXT_INCONSISTENT -> "Inconsistent authentication state";
            case RECENT_PERMISSION_CHANGE -> "Recent permission change";
            case PRIVILEGED_AUTHORIZATION -> "Privileged authorization request";
            case FRESH_MFA_REQUIRED -> "Fresh MFA required";
            case REQUEST_BURST -> "Short-time request increase";
            case RAPID_SEQUENCE -> "Rapid request sequence";
            case PREVIOUS_PATH_JUMP -> "Different flow from previous screen";
            case LOW_AUTH_ASSURANCE -> "Low authentication assurance";
            case BASELINE_MATERIAL_MISMATCH -> "Different from personal baseline";
            case SEMANTIC_EVIDENCE_MISMATCH -> "Different from allowed semantic evidence";
            case SEMANTIC_RISK_SIMILARITY -> "Similar to risk semantic evidence";
        };
    }

    private String signalCondition(HcadPreProtectablePromotionSignal signal) {
        return switch (signal) {
            case IMPOSSIBLE_TRAVEL -> "Stored impossible-travel indicator is true.";
            case FAILED_LOGIN_BURST -> "Stored failed-login burst count meets the configured threshold.";
            case AUTH_CONTEXT_INCONSISTENT -> "Trusted authentication context is internally inconsistent.";
            case RECENT_PERMISSION_CHANGE -> "Stored recent permission changes exist.";
            case PRIVILEGED_AUTHORIZATION -> "Bridge-verified authorization context marks the request as privileged.";
            case FRESH_MFA_REQUIRED -> "Verified resource requires fresh MFA and current MFA state is absent or stale.";
            case REQUEST_BURST -> "Stored request count meets the configured burst threshold.";
            case RAPID_SEQUENCE -> "Stored request sequence is marked rapid.";
            case PREVIOUS_PATH_JUMP -> "Stored previous path and current path indicate an unusual navigation jump.";
            case LOW_AUTH_ASSURANCE -> "Bridge-verified authentication assurance matches a configured low assurance value.";
            case BASELINE_MATERIAL_MISMATCH -> "Personal baseline comparison reports a material mismatch.";
            case SEMANTIC_EVIDENCE_MISMATCH -> "Fresh cached semantic evidence differs from prior allowed request evidence.";
            case SEMANTIC_RISK_SIMILARITY -> "Fresh cached semantic evidence is similar to verified risk evidence.";
        };
    }

    private String signalUnmetReason(HcadPreProtectablePromotionSignal signal, Map<String, Object> rawSnapshot) {
        if (signal == HcadPreProtectablePromotionSignal.SEMANTIC_EVIDENCE_MISMATCH
                || signal == HcadPreProtectablePromotionSignal.SEMANTIC_RISK_SIMILARITY) {
            Object semantic = rawSnapshot == null ? null : rawSnapshot.get("semanticEvidence");
            if (semantic instanceof Map<?, ?> map && Boolean.TRUE.equals(map.get("semanticEvidenceFreshHit"))) {
                return "SEMANTIC_THRESHOLD_NOT_MET";
            }
            return "FRESH_SEMANTIC_EVIDENCE_REQUIRED";
        }
        List<Map<String, Object>> fields = fieldExplanations(rawSnapshot, signal.requiredContractFields());
        boolean allAllowed = !fields.isEmpty()
                && fields.stream().allMatch(field -> Boolean.TRUE.equals(field.get("present"))
                && Boolean.TRUE.equals(field.get("scoringAllowed")));
        return allAllowed ? "CONDITION_NOT_MET" : "REQUIRED_TRUSTED_CONTEXT_ABSENT";
    }

    private Map<String, Object> contextExplanation(
            PendingAnomalyEvidenceReport report,
            Map<String, Object> rawSnapshot,
            String normalizedPath,
            String resourceId,
            String requestId) {
        Map<String, Object> context = new LinkedHashMap<>();
        context.put("userId", report == null ? null : report.userId());
        context.put("tenantId", rawSnapshot == null ? null : rawSnapshot.get("tenantId"));
        context.put("organizationId", rawSnapshot == null ? null : rawSnapshot.get("organizationId"));
        context.put("sessionId", report == null ? null : report.sessionId());
        context.put("contextBindingHash", report == null ? null : report.contextBindingHash());
        context.put("method", report == null ? null : report.httpMethod());
        context.put("normalizedPath", normalizedPath);
        context.put("resourceId", resourceId);
        context.put("requestId", requestId);
        context.put("windowId", rawSnapshot == null ? null : rawSnapshot.get("windowId"));
        context.put("actorSessionKey", rawSnapshot == null ? null : rawSnapshot.get("actorSessionKey"));
        context.put("source", "HCAD_TRUSTED_PROJECTION");
        return context;
    }

    private Map<String, Object> baselineExplanation(HcadBaselineComparison baselineComparison) {
        HcadBaselineComparison baseline = baselineComparison == null
                ? HcadBaselineComparison.unavailable(0)
                : baselineComparison;
        Map<String, Object> explanation = new LinkedHashMap<>();
        explanation.put("available", baseline.available());
        explanation.put("established", baseline.established());
        explanation.put("updateCount", baseline.updateCount());
        explanation.put("minSamples", baseline.minSamples());
        explanation.put("comparedDimensions", baseline.comparedDimensions());
        explanation.put("mismatchCount", baseline.mismatchCount());
        explanation.put("matchRatio", baseline.matchRatio());
        explanation.put("materialMismatch", baseline.materialMismatch());
        explanation.put("matchedDimensions", baseline.matchedDimensions());
        explanation.put("mismatchedDimensions", baseline.mismatchedDimensions());
        explanation.put("missingDimensions", baseline.missingDimensions());
        explanation.put("currentValues", baseline.currentValues());
        explanation.put("referenceValues", baseline.baselineValues());
        explanation.put("confidence", baseline.established() ? baseline.matchRatio() : 0.0d);
        explanation.put("confidenceSource", "baselineMatchRatio");
        explanation.put("lastUpdated", baseline.lastUpdated() == null ? null : baseline.lastUpdated().toString());
        explanation.put("lastUpdatedAgeSeconds", baseline.lastUpdated() == null
                ? null
                : Math.max(0L, Instant.now().getEpochSecond() - baseline.lastUpdated().getEpochSecond()));
        explanation.put("lastUpdatedStatus", baseline.lastUpdated() == null
                ? "NOT_RECORDED"
                : "RECORDED");
        explanation.put("dimensionExplanations", baselineDimensionExplanations(baseline));
        return explanation;
    }

    private List<Map<String, Object>> baselineDimensionExplanations(HcadBaselineComparison baseline) {
        if (baseline == null) {
            return List.of();
        }
        List<Map<String, Object>> explanations = new ArrayList<>();
        for (String dimension : baseline.mismatchedDimensions()) {
            explanations.add(baselineDimensionExplanation(baseline, dimension, "MISMATCH"));
        }
        for (String dimension : baseline.matchedDimensions()) {
            explanations.add(baselineDimensionExplanation(baseline, dimension, "MATCH"));
        }
        for (String dimension : baseline.missingDimensions()) {
            explanations.add(baselineDimensionExplanation(baseline, dimension, "MISSING"));
        }
        return explanations;
    }

    private Map<String, Object> baselineDimensionExplanation(
            HcadBaselineComparison baseline,
            String dimension,
            String status) {
        Map<String, Object> explanation = new LinkedHashMap<>();
        explanation.put("dimension", dimension);
        explanation.put("displayName", baselineDimensionDisplayName(dimension));
        explanation.put("status", status);
        explanation.put("currentValue", baseline.currentValues().get(dimension));
        explanation.put("referenceValue", baselineReferenceValue(baseline, dimension));
        explanation.put("weight", "MISMATCH".equals(status) && baseline.materialMismatch()
                ? HcadPreProtectablePromotionSignal.BASELINE_MATERIAL_MISMATCH.weight()
                : 0);
        return explanation;
    }

    private Object baselineReferenceValue(HcadBaselineComparison baseline, String dimension) {
        if (baseline == null || dimension == null) {
            return null;
        }
        Map<String, Object> values = baseline.baselineValues();
        return switch (dimension) {
            case "ipBand" -> firstPresent(values, "normalIpBands", "normalIpRanges");
            case "accessHour" -> values.get("normalAccessHours");
            case "accessDay" -> values.get("normalAccessDays");
            case "pathFamily" -> firstPresent(values, "frequentResourceFamilies", "frequentPaths");
            case "httpMethod" -> values.get("httpMethod");
            case "userAgent" -> values.get("normalUserAgents");
            case "operatingSystem" -> values.get("normalOperatingSystems");
            case "browser" -> values.get("normalBrowsers");
            case "authenticationType" -> values.get("normalAuthenticationTypes");
            default -> values.get(dimension);
        };
    }

    private Object firstPresent(Map<String, Object> values, String... keys) {
        if (values == null || keys == null) {
            return null;
        }
        for (String key : keys) {
            Object value = values.get(key);
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private String baselineDimensionDisplayName(String dimension) {
        return switch (dimension == null ? "" : dimension) {
            case "ipBand" -> "IP band";
            case "accessHour" -> "Access hour";
            case "accessDay" -> "Access day";
            case "pathFamily" -> "Screen/API family";
            case "httpMethod" -> "HTTP method";
            case "userAgent" -> "Browser signature";
            case "operatingSystem" -> "Operating system";
            case "browser" -> "Browser";
            case "authenticationType" -> "Authentication type";
            case "personalBaselineInsufficientSamples" -> "Insufficient baseline samples";
            case "personalBaselineUnavailable" -> "No personal baseline";
            default -> dimension;
        };
    }

    private Map<String, Object> rawSnapshotMap(Object rawSignals) {
        Map<String, Object> rawSnapshot = new LinkedHashMap<>();
        if (rawSignals instanceof Map<?, ?> map) {
            map.forEach((key, value) -> rawSnapshot.put(String.valueOf(key), value));
        }
        return rawSnapshot;
    }

    private List<?> valueAsList(Object value) {
        if (value instanceof List<?> list) {
            return list;
        }
        return List.of();
    }

    private Map<String, Object> semanticEvidenceExplanation(Map<String, Object> rawSnapshot) {
        Map<String, Object> explanation = new LinkedHashMap<>();
        Object semanticEvidence = rawSnapshot == null ? null : rawSnapshot.get("semanticEvidence");
        if (semanticEvidence instanceof Map<?, ?> semanticMap) {
            semanticMap.forEach((key, value) -> explanation.put(String.valueOf(key), value));
        } else {
            explanation.put("semanticEvidenceAvailable", false);
            explanation.put("semanticEvidenceGapCodes", List.of("SEMANTIC_EVIDENCE_NOT_RECORDED"));
            explanation.put("semanticEvidenceEntries", List.of());
        }
        explanation.put("cacheProvider", rawSnapshot == null ? null : rawSnapshot.get("semanticEvidenceCacheProvider"));
        explanation.put("cacheKeyType", "NORMAL_REQUEST_SIMILARITY/RISK_REQUEST_SIMILARITY");
        explanation.put("sourceTable", "ai_security_decision_observation");
        explanation.put("ttl", rawSnapshot == null ? null : rawSnapshot.get("semanticEvidenceTtl"));
        explanation.put("expiresAt", rawSnapshot == null ? null : rawSnapshot.get("semanticEvidenceExpiresAt"));
        explanation.put("freshnessEntries", rawSnapshot == null
                ? List.of()
                : valueAsList(rawSnapshot.get("semanticEvidenceFreshnessEntries")));
        explanation.put("ttlStatus", rawSnapshot != null && rawSnapshot.containsKey("semanticEvidenceExpiresAt")
                ? "RECORDED"
                : "NOT_RECORDED_IN_RAW_SNAPSHOT");
        return explanation;
    }

    private Map<String, Object> freshnessExplanation(
            Map<String, Object> rawSnapshot,
            HcadBaselineComparison baselineComparison) {
        Map<String, Object> freshness = new LinkedHashMap<>();
        freshness.put("windowId", rawSnapshot == null ? null : rawSnapshot.get("windowId"));
        freshness.put("requestCount", rawSnapshot == null ? null : rawSnapshot.get("requestCount"));
        freshness.put("duplicateSuppressedCount", rawSnapshot == null ? null : rawSnapshot.get("duplicateSuppressedCount"));
        freshness.put("negativeCacheHitCount", rawSnapshot == null ? null : rawSnapshot.get("negativeCacheHitCount"));
        freshness.put("observationWindowTtl", rawSnapshot == null ? null : rawSnapshot.get("observationWindowTtl"));
        freshness.put("observationWindowTtlStatus", rawSnapshot != null && rawSnapshot.containsKey("observationWindowTtl")
                ? "RECORDED"
                : "NOT_RECORDED_IN_RAW_SNAPSHOT");
        freshness.put("baselineUpdateCount", baselineComparison == null ? null : baselineComparison.updateCount());
        freshness.put("baselineLastUpdatedAge", "NOT_RECORDED_IN_BASELINE_COMPARISON");
        Object semanticEvidence = rawSnapshot == null ? null : rawSnapshot.get("semanticEvidence");
        if (semanticEvidence instanceof Map<?, ?> semanticMap) {
            freshness.put("semanticEvidenceFreshHit", semanticMap.get("semanticEvidenceFreshHit"));
            freshness.put("semanticEvidenceStaleHit", semanticMap.get("semanticEvidenceStaleHit"));
            freshness.put("semanticEvidenceGapCodes", semanticMap.get("semanticEvidenceGapCodes"));
        }
        return freshness;
    }

    private Map<String, Object> triggerExplanation(
            PendingAnomalyEvidenceReport report,
            String nonTriggerReason,
            String triggerDecisionReason,
            List<String> evidenceGaps) {
        Map<String, Object> explanation = new LinkedHashMap<>();
        explanation.put("shouldTrigger", report == null ? null : report.shouldTrigger());
        explanation.put("triggerDecisionReason", triggerDecisionReason);
        explanation.put("nonTriggerReason", nonTriggerReason);
        explanation.put("riskSignature", report == null ? null : report.riskSignature());
        explanation.put("triggerStateKey", report == null ? null : report.triggerStateKey());
        explanation.put("evidenceGapCodes", evidenceGaps);
        explanation.put("anchorSignals", report == null ? List.of() : report.anchorSignals());
        explanation.put("corroboratingSignals", report == null ? List.of() : report.corroboratingSignals());
        explanation.put("eligibleQuorum", report == null || report.rawSignalSnapshot() == null
                ? null
                : report.rawSignalSnapshot().get("eligibleQuorum"));
        explanation.put("eligibleFalseReasons", report == null || report.rawSignalSnapshot() == null
                ? List.of()
                : report.rawSignalSnapshot().get("eligibleFalseReasons"));
        explanation.put("reasonSummary", report == null ? null : report.reasonSummary());
        return explanation;
    }

    private Map<String, Object> triggerStateExplanation(
            String triggerDecisionReason,
            String nonTriggerReason,
            boolean triggeredLlm,
            String mergedRelation,
            String protectableResourceId,
            String protectableResourceUrl,
            String protectableHttpMethod) {
        Map<String, Object> explanation = new LinkedHashMap<>();
        explanation.put("triggerDecisionReason", triggerDecisionReason);
        explanation.put("nonTriggerReason", nonTriggerReason);
        explanation.put("triggeredLlm", triggeredLlm);
        explanation.put("modeSemantics", modeSemantics());
        if (mergedRelation != null || protectableResourceId != null || protectableResourceUrl != null || protectableHttpMethod != null) {
            Map<String, Object> merge = new LinkedHashMap<>();
            merge.put("relation", mergedRelation);
            merge.put("reason", "Same request reused the Protectable LLM decision instead of publishing a duplicate HCAD LLM trigger.");
            merge.put("protectableResourceId", protectableResourceId);
            merge.put("protectableResourceUrl", protectableResourceUrl);
            merge.put("protectableHttpMethod", protectableHttpMethod);
            explanation.put("mergeExplanation", merge);
        }
        return explanation;
    }

    private Map<String, Object> duplicateSuppressedExplanation(String existingEvaluationId, String nonTriggerReason) {
        Map<String, Object> explanation = triggerStateExplanation(
                "DUPLICATE_SUPPRESSED",
                nonTriggerReason,
                false,
                null,
                null,
                null,
                null);
        explanation.put("existingEvaluationId", existingEvaluationId);
        explanation.put("suppressionScope", "ACTOR_WINDOW");
        explanation.put("reason", "Repeated requests in the same actor window are counted on the existing HCAD evaluation instead of creating request-level rows.");
        return explanation;
    }

    private Map<String, Object> modeSemantics() {
        Map<String, Object> modes = new LinkedHashMap<>();
        modes.put("DISABLED", "HCAD does not evaluate or publish LLM triggers.");
        modes.put("OBSERVE", "HCAD may observe configured data but must not publish LLM triggers.");
        modes.put("SHADOW", "HCAD evaluates and records candidates; LLM decision remains non-enforcing.");
        modes.put("ENFORCE", "HCAD eligible trigger can publish an LLM analysis request according to policy.");
        return modes;
    }

    private Map<String, Object> valuesForFields(Map<String, Object> rawSnapshot, List<String> fields) {
        Map<String, Object> values = new LinkedHashMap<>();
        if (fields == null || fields.isEmpty()) {
            return values;
        }
        for (String field : fields) {
            values.put(field, rawSnapshot == null ? null : rawSnapshot.get(field));
        }
        return values;
    }

    private List<Map<String, Object>> fieldExplanations(Map<String, Object> rawSnapshot, List<String> fields) {
        if (fields == null || fields.isEmpty()) {
            return List.of();
        }
        Map<String, Object> provenance = provenanceMap(rawSnapshot);
        List<Map<String, Object>> explanations = new ArrayList<>();
        for (String field : fields) {
            HcadPromptSecurityContextFieldContract contract = HcadPromptSecurityContextFieldRegistry.contract(field);
            Object rawProvenance = provenance.get(field);
            String source = provenanceSource(rawProvenance);
            HcadTrustedSource trustedSource = trustedSource(source);
            Map<String, Object> explanation = new LinkedHashMap<>();
            explanation.put("field", field);
            explanation.put("value", rawSnapshot == null ? null : rawSnapshot.get(field));
            explanation.put("source", source);
            explanation.put("present", provenancePresent(rawProvenance, rawSnapshot != null && rawSnapshot.containsKey(field)));
            explanation.put("reason", provenanceReason(rawProvenance));
            explanation.put("source_field_path", contract == null ? null : contract.canonicalPath());
            explanation.put("sourceFieldPath", contract == null ? null : contract.canonicalPath());
            explanation.put("allowedSources", contract == null
                    ? List.of()
                    : contract.allowedSources().stream().map(Enum::name).toList());
            explanation.put("scoringAllowed", contract != null && contract.allowsScoringFrom(trustedSource));
            explanation.put("owner", contract == null ? null : contract.owner());
            explanation.put("normalizer", contract == null ? null : contract.normalizer());
            explanation.put("officialMetadataKey", contract == null ? null : contract.officialMetadataKey());
            explanations.add(explanation);
        }
        return explanations;
    }

    private Map<String, Object> provenanceMap(Map<String, Object> rawSnapshot) {
        Map<String, Object> provenance = new LinkedHashMap<>();
        Object raw = rawSnapshot == null ? null : rawSnapshot.get("signalProvenance");
        if (raw instanceof Map<?, ?> map) {
            map.forEach((key, value) -> provenance.put(String.valueOf(key), value));
        }
        return provenance;
    }

    private String provenanceSource(Object rawProvenance) {
        if (rawProvenance instanceof HcadFieldProvenance provenance) {
            return provenance.source().name();
        }
        if (rawProvenance instanceof Map<?, ?> map) {
            Object source = firstMapValue(map, "source", "trustedSource");
            if (source != null) {
                return source.toString();
            }
        }
        if (rawProvenance instanceof String text && !text.isBlank()) {
            return text;
        }
        return HcadTrustedSource.ABSENT.name();
    }

    private boolean provenancePresent(Object rawProvenance, boolean fallback) {
        if (rawProvenance instanceof HcadFieldProvenance provenance) {
            return provenance.present();
        }
        if (rawProvenance instanceof Map<?, ?> map) {
            Object present = firstMapValue(map, "present");
            if (present instanceof Boolean bool) {
                return bool;
            }
            if (present != null) {
                return Boolean.parseBoolean(present.toString());
            }
        }
        return fallback;
    }

    private String provenanceReason(Object rawProvenance) {
        if (rawProvenance instanceof HcadFieldProvenance provenance) {
            return provenance.reason();
        }
        if (rawProvenance instanceof Map<?, ?> map) {
            Object reason = firstMapValue(map, "reason");
            return reason == null ? null : reason.toString();
        }
        return null;
    }

    private Object firstMapValue(Map<?, ?> map, String... keys) {
        if (map == null || keys == null) {
            return null;
        }
        for (String key : keys) {
            if (map.containsKey(key)) {
                return map.get(key);
            }
        }
        return null;
    }

    private HcadTrustedSource trustedSource(String source) {
        if (source == null || source.isBlank()) {
            return HcadTrustedSource.ABSENT;
        }
        try {
            return HcadTrustedSource.valueOf(source);
        } catch (IllegalArgumentException ex) {
            return HcadTrustedSource.ABSENT;
        }
    }

    private Map<String, Object> baselineValuesForSignal(
            HcadPreProtectablePromotionSignal signal,
            HcadBaselineComparison baselineComparison) {
        Map<String, Object> values = new LinkedHashMap<>();
        if (signal != HcadPreProtectablePromotionSignal.BASELINE_MATERIAL_MISMATCH
                || baselineComparison == null) {
            return values;
        }
        values.put("referenceValues", baselineComparison.baselineValues());
        values.put("mismatchedDimensions", baselineComparison.mismatchedDimensions());
        values.put("missingDimensions", baselineComparison.missingDimensions());
        values.put("matchRatio", baselineComparison.matchRatio());
        return values;
    }

    private HcadBaselineComparison baselineComparison(Map<String, Object> rawSnapshot) {
        return baselineComparison(rawSnapshot == null ? null : rawSnapshot.get("baselineComparison"));
    }

    @SuppressWarnings("unchecked")
    private HcadBaselineComparison baselineComparison(Object raw) {
        Object baseline = raw;
        if (raw instanceof HcadBaselineComparison comparison) {
            return comparison;
        }
        if (raw instanceof Map<?, ?> map && map.containsKey("baselineComparison")) {
            baseline = map.get("baselineComparison");
        }
        if (baseline instanceof HcadBaselineComparison comparison) {
            return comparison;
        }
        if (baseline == null) {
            return HcadBaselineComparison.unavailable(0);
        }
        try {
            return objectMapper.convertValue(baseline, HcadBaselineComparison.class);
        } catch (IllegalArgumentException ex) {
            if (baseline instanceof Map<?, ?> map) {
                Map<String, Object> typed = (Map<String, Object>) map;
                return new HcadBaselineComparison(
                        boolDefault(bool(typed.get("available")), false),
                        boolDefault(bool(typed.get("established")), false),
                        longDefault(typed.get("updateCount"), 0L),
                        integerDefault(typed.get("minSamples"), 0),
                        integerDefault(typed.get("comparedDimensions"), 0),
                        integerDefault(typed.get("mismatchCount"), 0),
                        doubleDefault(typed.get("matchRatio"), 0.0d),
                        boolDefault(bool(typed.get("materialMismatch")), false),
                        stringList(typed.get("matchedDimensions")),
                        stringList(typed.get("mismatchedDimensions")),
                        stringList(typed.get("missingDimensions")),
                        Map.of(),
                        Map.of(),
                        instant(typed.get("lastUpdated")));
            }
            return HcadBaselineComparison.unavailable(0);
        }
    }

    @SuppressWarnings("unchecked")
    private List<String> semanticEvidenceGapCodes(Object rawSignals) {
        if (!(rawSignals instanceof Map<?, ?> map)) {
            return List.of();
        }
        Object semanticEvidence = map.get("semanticEvidence");
        if (!(semanticEvidence instanceof Map<?, ?> semanticMap)) {
            return List.of();
        }
        return stringList(((Map<String, Object>) semanticMap).get("semanticEvidenceGapCodes"));
    }

    private String resolveResourceId(Object rawSignals, String normalizedPath) {
        if (rawSignals instanceof Map<?, ?> map) {
            return firstNonBlank(
                    text(map.get("resourceId")),
                    text(map.get("resourceFamily")),
                    HcadRequestPathUtils.resourceFamily(normalizedPath));
        }
        return HcadRequestPathUtils.resourceFamily(normalizedPath);
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }

    private List<String> evidenceGapCodes(
            PendingAnomalyEvidenceReport report,
            HcadBaselineComparison baselineComparison) {
        return evidenceGapCodes(
                report == null ? List.of() : report.anchorSignals(),
                report == null ? List.of() : report.corroboratingSignals(),
                baselineComparison,
                report == null ? null : report.rawSignalSnapshot());
    }

    private List<String> evidenceGapCodes(
            Collection<String> anchorSignals,
            Collection<String> corroboratingSignals,
            HcadBaselineComparison baselineComparison) {
        return evidenceGapCodes(anchorSignals, corroboratingSignals, baselineComparison, null);
    }

    private List<String> evidenceGapCodes(
            Collection<String> anchorSignals,
            Collection<String> corroboratingSignals,
            HcadBaselineComparison baselineComparison,
            Object rawSignals) {
        List<String> gaps = new ArrayList<>();
        HcadBaselineComparison baseline = baselineComparison == null
                ? HcadBaselineComparison.unavailable(0)
                : baselineComparison;
        if (!baseline.available()) {
            if (baseline.missingDimensions().contains("personalBaselineInsufficientSamples")) {
                gaps.add("PERSONAL_BASELINE_INSUFFICIENT");
            } else {
                gaps.add("PERSONAL_BASELINE_UNAVAILABLE");
            }
        }
        if (isEmpty(anchorSignals)) {
            gaps.add("TRUSTED_ANCHOR_ABSENT");
        }
        if (isEmpty(corroboratingSignals)) {
            gaps.add("SUPPORTING_SIGNAL_ABSENT");
        }
        gaps.addAll(semanticEvidenceGapCodes(rawSignals));
        return List.copyOf(new LinkedHashSet<>(gaps));
    }

    private String nonTriggerReason(
            PendingAnomalyEvidenceReport report,
            HcadBaselineComparison baselineComparison,
            List<String> evidenceGaps) {
        if (report == null || report.shouldTrigger()) {
            return null;
        }
        return nonTriggerReason(
                report.anchorSignals(),
                report.corroboratingSignals(),
                baselineComparison,
                evidenceGaps);
    }

    private String nonTriggerReason(
            Collection<String> anchorSignals,
            Collection<String> corroboratingSignals,
            HcadBaselineComparison baselineComparison,
            List<String> evidenceGaps) {
        if (isEmpty(anchorSignals) && !isEmpty(corroboratingSignals)) {
            return "SUPPORTING_SIGNAL_ONLY";
        }
        if (isEmpty(anchorSignals)) {
            return "NO_TRUSTED_RISK_SIGNAL";
        }
        if (evidenceGaps != null && evidenceGaps.contains("PERSONAL_BASELINE_INSUFFICIENT")) {
            return "BASELINE_INSUFFICIENT";
        }
        HcadBaselineComparison baseline = baselineComparison == null
                ? HcadBaselineComparison.unavailable(0)
                : baselineComparison;
        if (!baseline.available()) {
            return "BASELINE_UNAVAILABLE";
        }
        return "BELOW_TRIGGER_THRESHOLD";
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
                        test_run_id,
                        user_id,
                        context_binding_hash,
                        actor_session_key,
                        window_id,
                        trigger_scope,
                        request_count,
                        http_method,
                        request_path,
                        normalized_path,
                        resource_id,
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
                        non_trigger_reason,
                        evidence_gap_codes,
                        baseline_available,
                        baseline_established,
                        baseline_update_count,
                        baseline_min_samples,
                        baseline_compared_dimensions,
                        baseline_mismatch_count,
                        baseline_match_ratio,
                        baseline_mismatched_dimensions,
                        baseline_current_values_json,
                        baseline_reference_values_json,
                        trigger_decision_reason,
                        signal_snapshot_json,
                        signal_provenance_json,
                        score_breakdown_json,
                        signal_explanations_json,
                        context_explanation_json,
                        baseline_explanation_json,
                        semantic_evidence_explanation_json,
                        freshness_explanation_json,
                        trigger_explanation_json,
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
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    evaluation.getEvaluationId(),
                    evaluation.getEventId(),
                    evaluation.getRequestId(),
                    evaluation.getCorrelationId(),
                    evaluation.getTestRunId(),
                    evaluation.getUserId(),
                    evaluation.getContextBindingHash(),
                    evaluation.getActorSessionKey(),
                    evaluation.getWindowId(),
                    blankToDefault(evaluation.getTriggerScope(), "SESSION_WINDOW"),
                    evaluation.getRequestCount() == null ? 1 : evaluation.getRequestCount(),
                    evaluation.getHttpMethod(),
                    evaluation.getRequestPath(),
                    evaluation.getNormalizedPath(),
                    evaluation.getResourceId(),
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
                    evaluation.getNonTriggerReason(),
                    evaluation.getEvidenceGapCodes(),
                    evaluation.getBaselineAvailable(),
                    evaluation.getBaselineEstablished(),
                    evaluation.getBaselineUpdateCount(),
                    evaluation.getBaselineMinSamples(),
                    evaluation.getBaselineComparedDimensions(),
                    evaluation.getBaselineMismatchCount(),
                    evaluation.getBaselineMatchRatio(),
                    evaluation.getBaselineMismatchedDimensions(),
                    evaluation.getBaselineCurrentValuesJson(),
                    evaluation.getBaselineReferenceValuesJson(),
                    evaluation.getTriggerDecisionReason(),
                    evaluation.getSignalSnapshotJson(),
                    evaluation.getSignalProvenanceJson(),
                    evaluation.getScoreBreakdownJson(),
                    evaluation.getSignalExplanationsJson(),
                    evaluation.getContextExplanationJson(),
                    evaluation.getBaselineExplanationJson(),
                    evaluation.getSemanticEvidenceExplanationJson(),
                    evaluation.getFreshnessExplanationJson(),
                    evaluation.getTriggerExplanationJson(),
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

    private TransactionOperations transactionOperations() {
        return transactionOperationsSupplier == null ? null : transactionOperationsSupplier.get();
    }

    private boolean isWriteTransactionActive() {
        return Boolean.TRUE.equals(writeTransactionActive.get());
    }

    private <T> T inWriteTransaction(Supplier<T> action) {
        if (action == null) {
            return null;
        }
        TransactionOperations transactionOperations = transactionOperations();
        if (transactionOperations == null) {
            writeTransactionActive.set(true);
            try {
                return action.get();
            } finally {
                writeTransactionActive.remove();
            }
        }
        return transactionOperations.execute(status -> {
            writeTransactionActive.set(true);
            try {
                return action.get();
            } finally {
                writeTransactionActive.remove();
            }
        });
    }

    private void inWriteTransaction(Runnable action) {
        if (action == null) {
            return;
        }
        inWriteTransaction(() -> {
            action.run();
            return null;
        });
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

    private String testRunId(Map<String, Object> metadata, Object rawSignals) {
        String direct = firstText(metadata,
                "testRunId",
                "hcadTestRunId",
                "hcadExtremeRunId",
                "xContexaTestRunId");
        if (direct != null) {
            return direct;
        }
        String nested = testRunId(rawSignals);
        if (nested != null) {
            return nested;
        }
        Object rawSignalSnapshot = metadata == null ? null : metadata.get("rawSignalSnapshot");
        return testRunId(rawSignalSnapshot);
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
                    return trimToLength(ignoredInputValue(entry.getValue()), 160);
                }
            }
        }
        return null;
    }

    private String ignoredInputValue(Object value) {
        if (value instanceof Map<?, ?> map) {
            Object extracted = map.get("value");
            if (extracted != null) {
                return text(extracted);
            }
        }
        return text(value);
    }

    private String trimToLength(String value, int maxLength) {
        if (value == null || maxLength <= 0 || value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength);
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
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private Long longDefault(Object value, long defaultValue) {
        Long resolved = longValue(value);
        return resolved == null ? defaultValue : resolved;
    }

    private Double doubleValue(Object value) {
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        String text = text(value);
        if (text == null) {
            return null;
        }
        try {
            return Double.parseDouble(text);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private Double doubleDefault(Object value, double defaultValue) {
        Double resolved = doubleValue(value);
        return resolved == null ? defaultValue : resolved;
    }

    private Instant instant(Object value) {
        if (value instanceof Instant instant) {
            return instant;
        }
        String text = text(value);
        if (text == null) {
            return null;
        }
        try {
            return Instant.parse(text);
        } catch (RuntimeException ignored) {
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

    private List<String> stringList(Object value) {
        if (value == null) {
            return List.of();
        }
        if (value instanceof Collection<?> collection) {
            return collection.stream()
                    .map(this::text)
                    .filter(item -> item != null && !item.isBlank())
                    .toList();
        }
        String text = text(value);
        if (text == null || "null".equalsIgnoreCase(text) || "[]".equals(text)) {
            return List.of();
        }
        if (text.startsWith("[") && text.endsWith("]")) {
            try {
                Object parsed = objectMapper.readValue(text, Object.class);
                if (parsed instanceof Collection<?> collection) {
                    return stringList(collection);
                }
            } catch (Exception ignored) {
                String inner = text.substring(1, text.length() - 1);
                if (inner.isBlank()) {
                    return List.of();
                }
                return List.of(inner.split(",")).stream()
                        .map(String::trim)
                        .map(item -> item.replace("\"", ""))
                        .filter(item -> !item.isBlank())
                        .toList();
            }
        }
        return List.of(text);
    }

    private boolean isEmpty(Collection<String> values) {
        return values == null || values.stream().noneMatch(value -> value != null && !value.isBlank());
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
