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
import io.contexa.contexacore.hcad.projection.HcadBaselineComparison;
import io.contexa.contexacore.hcad.trigger.HcadPreTriggerMode;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyEvidenceReport;
import io.contexa.contexacore.hcad.trigger.window.HcadObservationWindowLease;
import io.contexa.contexacore.repository.HcadDetectionEvaluationRepository;
import org.springframework.jdbc.core.JdbcOperations;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
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
        HcadBaselineComparison baselineComparison = baselineComparison(rawSnapshot);
        List<String> evidenceGaps = evidenceGapCodes(report, baselineComparison);
        String nonTriggerReason = report.shouldTrigger() ? null : nonTriggerReason(report, baselineComparison, evidenceGaps);
        HcadDetectionEvaluation evaluation = HcadDetectionEvaluation.builder()
                .evaluationId(evaluationId)
                .requestId(report.requestId())
                .correlationId(report.requestId())
                .testRunId(testRunId(rawSnapshot))
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
                .triggerDecisionReason(report.shouldTrigger() ? "TRIGGER_CANDIDATE" : nonTriggerReason)
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
                           non_trigger_reason = NULL,
                           trigger_decision_reason = 'TRIGGER_PUBLISHED',
                           triggered_at = ?
                     WHERE evaluation_id = ?
                    """, LocalDateTime.now(), evaluationId);
            return;
        }
        HcadDetectionEvaluationRepository repository = repository();
        if (repository != null) {
            repository.findById(evaluationId).ifPresent(evaluation -> {
                evaluation.setTriggeredLlm(true);
                evaluation.setNonTriggerReason(null);
                evaluation.setTriggerDecisionReason("TRIGGER_PUBLISHED");
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
                         , non_trigger_reason = COALESCE(non_trigger_reason, 'DUPLICATE_SUPPRESSED')
                         , trigger_decision_reason = 'DUPLICATE_SUPPRESSED'
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
                if (evaluation.getNonTriggerReason() == null || evaluation.getNonTriggerReason().isBlank()) {
                    evaluation.setNonTriggerReason("DUPLICATE_SUPPRESSED");
                }
                evaluation.setTriggerDecisionReason("DUPLICATE_SUPPRESSED");
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

        Object rawSignals = metadata.get(HcadPreProtectablePromotionAttributes.METADATA_RAW_SIGNALS);
        HcadBaselineComparison baselineComparison = baselineComparison(rawSignals);
        List<String> anchorSignals = stringList(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_ANCHOR_SIGNALS));
        List<String> corroboratingSignals = stringList(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_CORROBORATING_SIGNALS));
        List<String> evidenceGaps = evidenceGapCodes(anchorSignals, corroboratingSignals, baselineComparison);
        String evaluationId = UUID.randomUUID().toString();
        LocalDateTime now = LocalDateTime.now();
        HcadDetectionEvaluation evaluation = HcadDetectionEvaluation.builder()
                .evaluationId(evaluationId)
                .eventId(event != null ? event.getEventId() : null)
                .requestId(firstText(metadata, "requestId", "correlationId"))
                .correlationId(firstText(metadata, "correlationId", "requestId"))
                .testRunId(testRunId(metadata, rawSignals))
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
                .anchorSignals(writeJson(anchorSignals))
                .corroboratingSignals(writeJson(corroboratingSignals))
                .reasonCodes(writeJson(metadata.get(HcadPreProtectablePromotionAttributes.METADATA_REASON_CODES)))
                .nonTriggerReason(nonTriggerReason(anchorSignals, corroboratingSignals, baselineComparison, evidenceGaps))
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
                .triggerDecisionReason("OBSERVED_WITH_LLM_DECISION")
                .signalSnapshotJson(writeJson(rawSignals))
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
                        Map.of());
            }
            return HcadBaselineComparison.unavailable(0);
        }
    }

    private List<String> evidenceGapCodes(
            PendingAnomalyEvidenceReport report,
            HcadBaselineComparison baselineComparison) {
        return evidenceGapCodes(
                report == null ? List.of() : report.anchorSignals(),
                report == null ? List.of() : report.corroboratingSignals(),
                baselineComparison);
    }

    private List<String> evidenceGapCodes(
            Collection<String> anchorSignals,
            Collection<String> corroboratingSignals,
            HcadBaselineComparison baselineComparison) {
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
        return List.copyOf(gaps);
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
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
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
                    return text(entry.getValue());
                }
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
