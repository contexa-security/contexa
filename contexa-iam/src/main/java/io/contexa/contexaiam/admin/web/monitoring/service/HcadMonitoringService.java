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
package io.contexa.contexaiam.admin.web.monitoring.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.domain.entity.HcadDetectionEvaluation;
import io.contexa.contexacore.hcad.trigger.HcadPreTriggerMode;
import io.contexa.contexacore.properties.HcadProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.repository.HcadDetectionEvaluationRepository;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.MonitorSnapshot;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.RuntimeModeSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.Breakdown;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.CountBreakdown;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.HcadEvaluationExplanation;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.HcadSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.LlmDecisionExplanation;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.Qualification;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.RecentEvaluation;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.RequestExplanation;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.ScoreExplanation;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.ResourceBreakdown;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.ScoreBandBreakdown;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.UserSessionBreakdown;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class HcadMonitoringService {

    private static final int BREAKDOWN_LIMIT = 5;
    private static final int RECENT_LIMIT = 50;
    private static final DateTimeFormatter ISO = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    private final HcadDetectionEvaluationRepository repository;
    private final HcadProperties hcadProperties;
    private final SecurityZeroTrustProperties zeroTrustProperties;
    private final ObjectMapper objectMapper;

    public HcadMonitoringService(
            HcadDetectionEvaluationRepository repository,
            HcadProperties hcadProperties) {
        this(repository, hcadProperties, null);
    }

    public HcadMonitoringService(
            HcadDetectionEvaluationRepository repository,
            HcadProperties hcadProperties,
            ObjectMapper objectMapper) {
        this(repository, hcadProperties, objectMapper, null);
    }

    public HcadMonitoringService(
            HcadDetectionEvaluationRepository repository,
            HcadProperties hcadProperties,
            ObjectMapper objectMapper,
            SecurityZeroTrustProperties zeroTrustProperties) {
        this.repository = repository;
        this.hcadProperties = hcadProperties;
        this.zeroTrustProperties = zeroTrustProperties;
        this.objectMapper = objectMapper == null ? new ObjectMapper() : objectMapper;
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public HcadSummary summarize(String period) {
        String normalizedPeriod = normalizePeriod(period);
        LocalDateTime to = LocalDateTime.now();
        LocalDateTime from = switch (normalizedPeriod) {
            case "week" -> to.minusWeeks(1);
            case "month" -> to.minusMonths(1);
            case "year" -> to.minusYears(1);
            default -> to.minusDays(1);
        };
        return summarize(normalizedPeriod, from, to);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public HcadSummary summarize(String period, LocalDateTime from, LocalDateTime to) {
        String normalizedPeriod = normalizePeriod(period);

        long candidateCount = repository.countMonitorableByCreatedAtBetween(from, to);
        long observedRequestCount = longValue(repository.sumMonitorableRequestCountBetween(from, to));
        long triggeredLlmCount = repository.countMonitorableByTriggeredLlmTrueAndCreatedAtBetween(from, to);
        long duplicateSuppressedCount = longValue(repository.sumMonitorableDuplicateSuppressedCountBetween(from, to));
        long eligibleCount = repository.countMonitorableByEligibleTrueAndCreatedAtBetween(from, to);
        long notEligibleCount = repository.countMonitorableByEligibleFalseAndCreatedAtBetween(from, to);
        long negativeCacheHitCount = longValue(repository.sumMonitorableNegativeCacheHitCountBetween(from, to));
        long escalationCount = repository.countMonitorableEscalationBetween(from, to);
        long tp = repository.countMonitorableComparableByOutcomeClassAndCreatedAtBetween("TP", from, to);
        long fp = repository.countMonitorableComparableByOutcomeClassAndCreatedAtBetween("FP", from, to);
        long fn = repository.countMonitorableComparableByOutcomeClassAndCreatedAtBetween("FN", from, to);
        long tn = repository.countMonitorableComparableByOutcomeClassAndCreatedAtBetween("TN", from, to);
        long unknown = repository.countMonitorableComparableByOutcomeClassAndCreatedAtBetween("UNKNOWN", from, to);
        double precision = precision(tp, fp);
        double unknownRate = ratio(unknown, tp + fp + fn + tn + unknown);
        double triggerRate = ratio(triggeredLlmCount, candidateCount);
        double averageLatency = doubleValue(repository.averageMonitorableLlmLatencyMsBetween(from, to));

        HcadProperties.PreTriggerSettings.QualificationSettings q =
                hcadProperties.getPreTrigger().getQualification();
        double estimatedWasteCost = fp * q.getEstimatedLlmCallCostUsd();
        double estimatedSavedCost = duplicateSuppressedCount * q.getEstimatedLlmCallCostUsd();

        return new HcadSummary(
                normalizedPeriod,
                ISO.format(from),
                ISO.format(to),
                ISO.format(to),
                new MonitorSnapshot(normalizedPeriod, ISO.format(from), ISO.format(to), ISO.format(to), runtimeModeSummary()),
                hcadProperties.getPreTrigger().effectiveMode().metadataValue(),
                candidateCount,
                observedRequestCount,
                triggeredLlmCount,
                eligibleCount,
                notEligibleCount,
                triggerRate,
                tp,
                fp,
                fn,
                tn,
                unknown,
                duplicateSuppressedCount,
                negativeCacheHitCount,
                escalationCount,
                precision,
                unknownRate,
                averageLatency,
                fp,
                estimatedWasteCost,
                estimatedSavedCost,
                new Qualification(
                        q.getShadowMinPrecision(),
                        q.getLimitedEnforceMinPrecision(),
                        q.getDefaultEnforceMinPrecision(),
                        q.getMinimumSampleSize(),
                        q.getEstimatedLlmCallCostUsd()),
                recommendation(candidateCount, precision, q),
                modeBreakdown(from, to),
                signalBreakdown(from, to),
                countBreakdown(repository.countByScoreBetween(from, to)),
                countBreakdown(repository.countByBandBetween(from, to)),
                scoreBandBreakdown(from, to),
                anchorSignalBreakdown(from, to),
                corroboratingSignalBreakdown(from, to),
                resourceBreakdown(from, to),
                userSessionBreakdown(from, to),
                nonTriggerReasonBreakdown(from, to),
                evidenceCoverageBreakdown(from, to),
                recentEvaluations(from, to),
                unknownEvaluations(from, to));
    }

    private RuntimeModeSummary runtimeModeSummary() {
        HcadPreTriggerMode hcadMode = hcadProperties == null
                ? HcadPreTriggerMode.SHADOW
                : hcadProperties.getPreTrigger().effectiveMode();
        SecurityZeroTrustProperties.SecurityMode llmMode = zeroTrustProperties == null
                ? SecurityZeroTrustProperties.SecurityMode.ENFORCE
                : zeroTrustProperties.getMode();
        return new RuntimeModeSummary(
                hcadMode.metadataValue(),
                hcadEffectKey(hcadMode),
                llmMode.name(),
                llmEffectKey(llmMode));
    }

    private String hcadEffectKey(HcadPreTriggerMode mode) {
        return switch (mode) {
            case DISABLED -> "HCAD_DISABLED";
            case OBSERVE -> "HCAD_OBSERVE_LOG_ONLY";
            case SHADOW -> "HCAD_SHADOW_LOG_ONLY";
            case ENFORCE -> "HCAD_ENFORCE_LLM_TRIGGER_ACTION_LOG";
        };
    }

    private String llmEffectKey(SecurityZeroTrustProperties.SecurityMode mode) {
        return switch (mode) {
            case DISABLED -> "LLM_DISABLED";
            case OBSERVE -> "LLM_OBSERVE_LOG_ONLY";
            case SHADOW -> "LLM_SHADOW_LOG_ONLY";
            case ENFORCE -> "LLM_ENFORCE_ACTION_LOG";
        };
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public String exportCsv(String period) {
        return exportCsv(period, Locale.ENGLISH);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public HcadEvaluationExplanation explainEvaluation(String evaluationId) {
        if (evaluationId == null || evaluationId.isBlank()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "HCAD evaluation not found");
        }
        HcadDetectionEvaluation evaluation = repository.findById(evaluationId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "HCAD evaluation not found"));
        Map<String, Object> rawSignalSnapshot = readMap(evaluation.getSignalSnapshotJson());
        return new HcadEvaluationExplanation(
                evaluation.getEvaluationId(),
                new RequestExplanation(
                        evaluation.getRequestId(),
                        evaluation.getEventId(),
                        evaluation.getCorrelationId(),
                        evaluation.getTestRunId(),
                        evaluation.getUserId(),
                        evaluation.getActorSessionKey(),
                        evaluation.getContextBindingHash(),
                        evaluation.getWindowId(),
                        evaluation.getHttpMethod(),
                        evaluation.getRequestPath(),
                        evaluation.getNormalizedPath(),
                        evaluation.getResourceId(),
                        evaluation.getMode(),
                        format(evaluation.getCreatedAt()),
                        format(evaluation.getTriggeredAt()),
                        format(evaluation.getDecidedAt())),
                new ScoreExplanation(
                        evaluation.getEarlyAnalysisScore(),
                        evaluation.getBand(),
                        evaluation.getEligible(),
                        evaluation.getTriggeredLlm(),
                        evaluation.getDuplicateSuppressed(),
                        evaluation.getDuplicateSuppressedCount(),
                        firstText(evaluation.getNonTriggerReason(), inferredNonTriggerReason(
                                evaluation,
                                readStringList(evaluation.getAnchorSignals()),
                                readStringList(evaluation.getCorroboratingSignals()))),
                        evaluation.getTriggerDecisionReason(),
                        evaluation.getOutcomeClass()),
                readMap(evaluation.getScoreBreakdownJson()),
                readMapList(evaluation.getSignalExplanationsJson()),
                readMap(evaluation.getContextExplanationJson()),
                readMap(evaluation.getBaselineExplanationJson()),
                readMap(evaluation.getSemanticEvidenceExplanationJson()),
                readMap(evaluation.getFreshnessExplanationJson()),
                readMap(evaluation.getTriggerExplanationJson()),
                readMap(evaluation.getSignalProvenanceJson()),
                rawSignalSnapshot,
                readStringListFromObject(rawSignalSnapshot.get("ignoredInputs")),
                new LlmDecisionExplanation(
                        evaluation.getLlmAction(),
                        evaluation.getLlmProposedAction(),
                        evaluation.getLlmRiskScore(),
                        evaluation.getLlmConfidence(),
                        evaluation.getLlmLatencyMs(),
                        evaluation.getLlmParserFailure(),
                        evaluation.getLlmTechnicalFallback(),
                        evaluation.getLlmFallbackCategory(),
                        evaluation.getLlmFallbackReason(),
                        evaluation.getLlmReasoningSummary(),
                        evaluation.getLlmReasoningHash()));
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public String exportCsv(String period, Locale locale) {
        HcadSummary summary = summarize(period);
        boolean korean = locale != null && "ko".equalsIgnoreCase(locale.getLanguage());
        StringBuilder csv = new StringBuilder();
        csv.append(String.join(",",
                csv(label(korean, "\uAE30\uAC04", "period")),
                csv(label(korean, "\uC2DC\uC791", "from")),
                csv(label(korean, "\uC885\uB8CC", "to")),
                csv(label(korean, "\uD604\uC7AC \uBAA8\uB4DC", "currentMode")),
                csv(label(korean, "HCAD \uC708\uB3C4\uC6B0", "hcadWindows")),
                csv(label(korean, "\uAD00\uCE21 \uC694\uCCAD", "observedRequests")),
                csv(label(korean, "LLM \uD638\uCD9C", "llmCalls")),
                csv(label(korean, "HCAD \uD3C9\uAC00 \uB300\uC0C1", "hcadEligible")),
                csv(label(korean, "HCAD \uD3C9\uAC00 \uC81C\uC678", "hcadNotEligible")),
                csv(label(korean, "\uC870\uAE30\uD0D0\uC9C0 \uBC1C\uC0DD\uB960", "triggerRate")),
                csv(label(korean, "\uC815\uBC00\uB3C4", "precision")),
                csv(label(korean, "\uC624\uD0D0", "falsePositive")),
                csv(label(korean, "\uAD00\uCE21 \uAC00\uB2A5 \uBBF8\uD0D0", "observableFalseNegative")),
                csv(label(korean, "\uBD88\uBA85\uD655", "unknown")),
                csv(label(korean, "\uC911\uBCF5 \uC5B5\uC81C", "duplicates")),
                csv(label(korean, "Negative cache \uC801\uC911", "negativeCacheHit")),
                csv(label(korean, "\uC2B9\uACA9", "escalation")),
                csv(label(korean, "\uD3C9\uADE0 \uC9C0\uC5F0(ms)", "averageLatencyMs")),
                csv(label(korean, "\uB0AD\uBE44 \uBE44\uC6A9", "wasteCostUsd")),
                csv(label(korean, "\uC808\uAC10 \uBE44\uC6A9", "savedCostUsd")),
                csv(label(korean, "\uAD8C\uC7A5 \uC0C1\uD0DC", "recommendation")))).append('\n');
        csv.append(csv(summary.period())).append(',')
                .append(csv(summary.from())).append(',')
                .append(csv(summary.to())).append(',')
                .append(csv(summary.currentMode())).append(',')
                .append(summary.candidateCount()).append(',')
                .append(summary.observedRequestCount()).append(',')
                .append(summary.triggeredLlmCount()).append(',')
                .append(summary.eligibleCount()).append(',')
                .append(summary.notEligibleCount()).append(',')
                .append(summary.triggerRate()).append(',')
                .append(summary.precision()).append(',')
                .append(summary.falsePositiveCount()).append(',')
                .append(summary.observableFalseNegativeCount()).append(',')
                .append(summary.unknownCount()).append(',')
                .append(summary.duplicateSuppressedCount()).append(',')
                .append(summary.negativeCacheHitCount()).append(',')
                .append(summary.escalationCount()).append(',')
                .append(summary.averageLlmLatencyMs()).append(',')
                .append(summary.estimatedWasteCostUsd()).append(',')
                .append(summary.estimatedSavedCostUsd()).append(',')
                .append(csv(summary.recommendation())).append('\n');
        csv.append('\n');
        csv.append(String.join(",",
                csv(label(korean, "\uC0DD\uC131 \uC2DC\uAC01", "createdAt")),
                csv(label(korean, "\uC0AC\uC6A9\uC790", "userId")),
                csv(label(korean, "\uBA54\uC11C\uB4DC", "method")),
                csv(label(korean, "\uACBD\uB85C", "path")),
                csv(label(korean, "\uC810\uC218", "score")),
                csv("band"),
                csv(label(korean, "LLM \uD638\uCD9C", "triggeredLlm")),
                csv(label(korean, "\uC911\uBCF5 \uC5B5\uC81C", "duplicateSuppressed")),
                csv(label(korean, "LLM \uC561\uC158", "llmAction")),
                csv(label(korean, "LLM \uC704\uD5D8 \uC810\uC218", "llmRiskScore")),
                csv(label(korean, "LLM \uC2E0\uB8B0\uB3C4", "llmConfidence")),
                csv(label(korean, "\uD30C\uC11C \uC2E4\uD328", "parserFailure")),
                csv(label(korean, "\uAE30\uC220\uC801 \uB300\uCCB4 \uCC98\uB9AC", "technicalFallback")),
                csv(label(korean, "\uB300\uCCB4 \uCC98\uB9AC \uBD84\uB958", "fallbackCategory")),
                csv(label(korean, "\uACB0\uACFC", "outcome")))).append('\n');
        for (RecentEvaluation evaluation : summary.recentEvaluations()) {
            csv.append(csv(evaluation.createdAt())).append(',')
                    .append(csv(evaluation.userId())).append(',')
                    .append(csv(evaluation.method())).append(',')
                    .append(csv(evaluation.path())).append(',')
                    .append(evaluation.earlyAnalysisScore() == null ? "" : evaluation.earlyAnalysisScore()).append(',')
                    .append(csv(evaluation.band())).append(',')
                    .append(evaluation.triggeredLlm() == null ? "" : evaluation.triggeredLlm()).append(',')
                    .append(evaluation.duplicateSuppressed() == null ? "" : evaluation.duplicateSuppressed()).append(',')
                    .append(csv(evaluation.llmAction())).append(',')
                    .append(evaluation.llmRiskScore() == null ? "" : evaluation.llmRiskScore()).append(',')
                    .append(evaluation.llmConfidence() == null ? "" : evaluation.llmConfidence()).append(',')
                    .append(evaluation.llmParserFailure() == null ? "" : evaluation.llmParserFailure()).append(',')
                    .append(evaluation.llmTechnicalFallback() == null ? "" : evaluation.llmTechnicalFallback()).append(',')
                    .append(csv(evaluation.llmFallbackCategory())).append(',')
                    .append(csv(evaluation.outcomeClass())).append('\n');
        }
        return csv.toString();
    }

    private List<Breakdown> modeBreakdown(LocalDateTime from, LocalDateTime to) {
        return repository.countMonitorableByModeBetween(from, to).stream()
                .map(row -> new Breakdown(text(row, 0), number(row, 1), 0, 0, 0, 0.0d))
                .toList();
    }

    private List<Breakdown> signalBreakdown(LocalDateTime from, LocalDateTime to) {
        return repository.aggregateBySignalBetween(from, to, BREAKDOWN_LIMIT).stream()
                .map(row -> {
                    long tp = number(row, 2);
                    long fp = number(row, 3);
                    return new Breakdown(text(row, 0), number(row, 1), tp, fp, number(row, 4), precision(tp, fp));
                })
                .toList();
    }

    private List<CountBreakdown> countBreakdown(List<Object[]> rows) {
        return rows.stream()
                .map(row -> new CountBreakdown(text(row, 0), number(row, 1)))
                .toList();
    }

    private List<ScoreBandBreakdown> scoreBandBreakdown(LocalDateTime from, LocalDateTime to) {
        return repository.countByScoreBandBetween(from, to).stream()
                .map(row -> new ScoreBandBreakdown(
                        text(row, 0),
                        number(row, 1),
                        number(row, 2),
                        number(row, 3),
                        number(row, 4),
                        number(row, 5),
                        number(row, 6)))
                .toList();
    }

    private List<Breakdown> anchorSignalBreakdown(LocalDateTime from, LocalDateTime to) {
        return repository.aggregateByAnchorSignalBetween(from, to, BREAKDOWN_LIMIT).stream()
                .map(row -> {
                    long tp = number(row, 2);
                    long fp = number(row, 3);
                    return new Breakdown(text(row, 0), number(row, 1), tp, fp, number(row, 4), precision(tp, fp));
                })
                .toList();
    }

    private List<Breakdown> corroboratingSignalBreakdown(LocalDateTime from, LocalDateTime to) {
        return repository.aggregateByCorroboratingSignalBetween(from, to, BREAKDOWN_LIMIT).stream()
                .map(row -> {
                    long tp = number(row, 2);
                    long fp = number(row, 3);
                    return new Breakdown(text(row, 0), number(row, 1), tp, fp, number(row, 4), precision(tp, fp));
                })
                .toList();
    }

    private List<ResourceBreakdown> resourceBreakdown(LocalDateTime from, LocalDateTime to) {
        return repository.aggregateByResourceBetween(from, to, BREAKDOWN_LIMIT).stream()
                .map(row -> {
                    long tp = number(row, 3);
                    long fp = number(row, 4);
                    return new ResourceBreakdown(
                            text(row, 0),
                            text(row, 1),
                            number(row, 2),
                            tp,
                            fp,
                            number(row, 5),
                            precision(tp, fp));
                })
                .toList();
    }

    private List<UserSessionBreakdown> userSessionBreakdown(LocalDateTime from, LocalDateTime to) {
        return repository.aggregateByUserSessionBetween(from, to, BREAKDOWN_LIMIT).stream()
                .map(row -> {
                    long tp = number(row, 5);
                    long fp = number(row, 6);
                    return new UserSessionBreakdown(
                            text(row, 0),
                            text(row, 1),
                            number(row, 2),
                            number(row, 3),
                            number(row, 4),
                            tp,
                            fp,
                            number(row, 7),
                            precision(tp, fp));
                })
                .toList();
    }

    private List<CountBreakdown> nonTriggerReasonBreakdown(LocalDateTime from, LocalDateTime to) {
        return repository.countMonitorableNonTriggerReasonsBetween(from, to).stream()
                .map(row -> new CountBreakdown(text(row, 0), number(row, 1)))
                .toList();
    }

    private List<CountBreakdown> evidenceCoverageBreakdown(LocalDateTime from, LocalDateTime to) {
        return repository.countMonitorableEvidenceCoverageBetween(from, to).stream()
                .map(row -> new CountBreakdown(text(row, 0), number(row, 1)))
                .toList();
    }

    private List<RecentEvaluation> recentEvaluations(LocalDateTime from, LocalDateTime to) {
        return repository.findTop50MonitorableByCreatedAtBetweenOrderByCreatedAtDesc(from, to).stream()
                .limit(RECENT_LIMIT)
                .map(this::toRecentEvaluation)
                .toList();
    }

    private List<RecentEvaluation> unknownEvaluations(LocalDateTime from, LocalDateTime to) {
        return repository.findTop25MonitorableByOutcomeClassAndCreatedAtBetweenOrderByCreatedAtDesc("UNKNOWN", from, to).stream()
                .limit(BREAKDOWN_LIMIT)
                .map(this::toRecentEvaluation)
                .toList();
    }

    private RecentEvaluation toRecentEvaluation(HcadDetectionEvaluation evaluation) {
        List<String> anchorSignals = readStringList(evaluation.getAnchorSignals());
        List<String> corroboratingSignals = readStringList(evaluation.getCorroboratingSignals());
        return new RecentEvaluation(
                evaluation.getEvaluationId(),
                evaluation.getRequestId(),
                evaluation.getUserId(),
                evaluation.getHttpMethod(),
                evaluation.getRequestPath(),
                evaluation.getMode(),
                evaluation.getEarlyAnalysisScore(),
                evaluation.getBand(),
                evaluation.getTriggeredLlm(),
                evaluation.getDuplicateSuppressed(),
                evaluation.getLlmAction(),
                evaluation.getLlmRiskScore(),
                evaluation.getLlmConfidence(),
                evaluation.getLlmParserFailure(),
                evaluation.getLlmTechnicalFallback(),
                evaluation.getLlmFallbackCategory(),
                evaluation.getOutcomeClass(),
                anchorSignals,
                corroboratingSignals,
                readStringList(evaluation.getReasonCodes()),
                firstText(evaluation.getNonTriggerReason(), inferredNonTriggerReason(evaluation, anchorSignals, corroboratingSignals)),
                evidenceGaps(evaluation, anchorSignals, corroboratingSignals),
                readSnapshotText(evaluation.getSignalSnapshotJson(), "promptContextContractVersion"),
                baselineComparisonSummaryV2(evaluation.getSignalSnapshotJson()),
                format(evaluation.getCreatedAt()),
                format(evaluation.getDecidedAt()));
    }

    private List<String> readStringList(String json) {
        if (json == null || json.isBlank() || "null".equalsIgnoreCase(json.trim())) {
            return List.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<List<String>>() {
            });
        } catch (Exception ignored) {
            return Arrays.stream(json.replace("[", "").replace("]", "").split(","))
                    .map(String::trim)
                    .filter(value -> !value.isBlank())
                    .toList();
        }
    }

    private List<String> readStringListFromObject(Object raw) {
        if (raw == null) {
            return List.of();
        }
        if (raw instanceof List<?> list) {
            return list.stream()
                    .filter(value -> value != null && !value.toString().isBlank())
                    .map(Object::toString)
                    .toList();
        }
        if (raw instanceof String text) {
            return readStringList(text);
        }
        return List.of(raw.toString());
    }

    private String readSnapshotText(String json, String key) {
        MapSnapshot snapshot = readSnapshot(json);
        Object value = snapshot.values().get(key);
        return value == null ? null : value.toString();
    }

    private String inferredNonTriggerReason(
            HcadDetectionEvaluation evaluation,
            List<String> anchorSignals,
            List<String> corroboratingSignals) {
        if (Boolean.TRUE.equals(evaluation.getTriggeredLlm())) {
            return "TRIGGERED_LLM";
        }
        if (Boolean.TRUE.equals(evaluation.getDuplicateSuppressed())
                || (evaluation.getDuplicateSuppressedCount() != null && evaluation.getDuplicateSuppressedCount() > 0)) {
            return "DUPLICATE_SUPPRESSED";
        }
        if (Boolean.TRUE.equals(evaluation.getNegativeCacheHit())
                || (evaluation.getNegativeCacheHitCount() != null && evaluation.getNegativeCacheHitCount() > 0)) {
            return "NEGATIVE_CACHE_HIT";
        }
        if (anchorSignals.isEmpty() && !corroboratingSignals.isEmpty()) {
            return "SUPPORTING_SIGNAL_ONLY";
        }
        if (anchorSignals.isEmpty()) {
            return "NO_TRUSTED_RISK_SIGNAL";
        }
        if (Boolean.TRUE.equals(evaluation.getEligible())) {
            return "ELIGIBLE_BUT_NOT_PUBLISHED";
        }
        return "BELOW_TRIGGER_THRESHOLD";
    }

    private List<String> evidenceGaps(
            HcadDetectionEvaluation evaluation,
            List<String> anchorSignals,
            List<String> corroboratingSignals) {
        List<String> persisted = readStringList(evaluation.getEvidenceGapCodes());
        if (!persisted.isEmpty()) {
            return persisted;
        }
        List<String> gaps = new ArrayList<>();
        MapSnapshot snapshot = readSnapshot(evaluation.getSignalSnapshotJson());
        Object raw = snapshot.values().get("baselineComparison");
        if (raw instanceof Map<?, ?> baseline) {
            Object available = baseline.get("available");
            Object missing = baseline.get("missingDimensions");
            if (!Boolean.TRUE.equals(available) && !"true".equalsIgnoreCase(String.valueOf(available))) {
                if (missing != null && missing.toString().contains("personalBaselineInsufficientSamples")) {
                    gaps.add("PERSONAL_BASELINE_INSUFFICIENT");
                } else {
                    gaps.add("PERSONAL_BASELINE_UNAVAILABLE");
                }
            }
        } else if (evaluation.getBaselineAvailable() == null || !evaluation.getBaselineAvailable()) {
            gaps.add("PERSONAL_BASELINE_UNAVAILABLE");
        }
        if (anchorSignals.isEmpty()) {
            gaps.add("TRUSTED_ANCHOR_ABSENT");
        }
        if (corroboratingSignals.isEmpty()) {
            gaps.add("SUPPORTING_SIGNAL_ABSENT");
        }
        return gaps.stream().distinct().toList();
    }

    private String baselineComparisonSummaryV2(String json) {
        MapSnapshot snapshot = readSnapshot(json);
        Object raw = snapshot.values().get("baselineComparison");
        if (!(raw instanceof Map<?, ?> baseline)) {
            return null;
        }
        Object available = baseline.get("available");
        Object missingDimensions = baseline.get("missingDimensions");
        if (!Boolean.TRUE.equals(available) && !"true".equalsIgnoreCase(String.valueOf(available))) {
            if (missingDimensions != null && missingDimensions.toString().contains("personalBaselineInsufficientSamples")) {
                return "개인 기준선 표본이 아직 부족함";
            }
            return "개인 기준선 없음";
        }
        boolean mismatch = Boolean.TRUE.equals(baseline.get("materialMismatch"));
        String ratioText = baseline.get("matchRatio") == null ? "-" : baseline.get("matchRatio").toString();
        String countText = baseline.get("mismatchCount") == null ? "0" : baseline.get("mismatchCount").toString();
        if (!mismatch) {
            return "평소 패턴과 큰 차이 없음";
        }
        return "평소 패턴과 다른 항목 " + countText + "건, 일치율 " + ratioText
                + ", 항목 " + baseline.get("mismatchedDimensions");
    }
    private String baselineComparisonSummary(String json) {
        MapSnapshot snapshot = readSnapshot(json);
        Object raw = snapshot.values().get("baselineComparison");
        if (!(raw instanceof Map<?, ?> baseline)) {
            return null;
        }
        Object materialMismatch = baseline.get("materialMismatch");
        Object mismatchCount = baseline.get("mismatchCount");
        Object matchRatio = baseline.get("matchRatio");
        Object mismatchedDimensions = baseline.get("mismatchedDimensions");
        boolean mismatch = Boolean.TRUE.equals(materialMismatch);
        String ratioText = matchRatio == null ? "-" : matchRatio.toString();
        String countText = mismatchCount == null ? "0" : mismatchCount.toString();
        if (!mismatch) {
            return "평소 패턴과 큰 차이 없음";
        }
        return "평소 패턴과 다른 항목 " + countText + "건, 일치율 " + ratioText
                + ", 항목 " + mismatchedDimensions;
    }
    private MapSnapshot readSnapshot(String json) {
        if (json == null || json.isBlank() || "null".equalsIgnoreCase(json.trim())) {
            return new MapSnapshot(Map.of());
        }
        try {
            return new MapSnapshot(objectMapper.readValue(json, new TypeReference<Map<String, Object>>() {
            }));
        } catch (Exception ignored) {
            return new MapSnapshot(Map.of());
        }
    }

    private Map<String, Object> readMap(String json) {
        return readSnapshot(json).values();
    }

    private List<Map<String, Object>> readMapList(String json) {
        if (json == null || json.isBlank() || "null".equalsIgnoreCase(json.trim())) {
            return List.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<List<Map<String, Object>>>() {
            });
        } catch (Exception ignored) {
            Map<String, Object> asMap = readMap(json);
            return asMap.isEmpty() ? List.of() : List.of(asMap);
        }
    }

    private String recommendation(
            long sampleSize,
            double precision,
            HcadProperties.PreTriggerSettings.QualificationSettings qualification) {
        if (sampleSize < qualification.getMinimumSampleSize()) {
            return "INSUFFICIENT_SAMPLE";
        }
        if (precision >= qualification.getDefaultEnforceMinPrecision()) {
            return "DEFAULT_ENFORCE_CANDIDATE";
        }
        if (precision >= qualification.getLimitedEnforceMinPrecision()) {
            return "LIMITED_ENFORCE_CANDIDATE";
        }
        if (precision >= qualification.getShadowMinPrecision()) {
            return "SHADOW_STABLE";
        }
        return "KEEP_SHADOW";
    }

    private String normalizePeriod(String period) {
        if (period == null || period.isBlank()) {
            return "day";
        }
        String normalized = period.trim().toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "week", "month", "year" -> normalized;
            default -> "day";
        };
    }

    private double precision(long tp, long fp) {
        long denominator = tp + fp;
        return denominator <= 0 ? 0.0d : (double) tp / denominator;
    }

    private double ratio(long numerator, long denominator) {
        return denominator <= 0 ? 0.0d : (double) numerator / denominator;
    }

    private String text(Object[] row, int index) {
        if (row == null || row.length <= index || row[index] == null) {
            return "";
        }
        return row[index].toString();
    }

    private String firstText(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    private long number(Object[] row, int index) {
        if (row == null || row.length <= index || row[index] == null) {
            return 0L;
        }
        if (row[index] instanceof Number number) {
            return number.longValue();
        }
        return Long.parseLong(row[index].toString());
    }

    private double doubleValue(Number value) {
        return value == null ? 0.0d : value.doubleValue();
    }

    private long longValue(Number value) {
        return value == null ? 0L : value.longValue();
    }

    private String format(LocalDateTime value) {
        return value == null ? null : ISO.format(value);
    }

    private String csv(Object value) {
        if (value == null) {
            return "";
        }
        String text = value.toString();
        if (text.contains(",") || text.contains("\"") || text.contains("\n") || text.contains("\r")) {
            return "\"" + text.replace("\"", "\"\"") + "\"";
        }
        return text;
    }

    private String label(boolean korean, String ko, String en) {
        return korean ? ko : en;
    }

    private record MapSnapshot(Map<String, Object> values) {
    }
}
