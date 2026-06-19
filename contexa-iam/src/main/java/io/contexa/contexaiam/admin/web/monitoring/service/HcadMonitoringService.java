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

import io.contexa.contexacore.domain.entity.HcadDetectionEvaluation;
import io.contexa.contexacore.properties.HcadProperties;
import io.contexa.contexacore.repository.HcadDetectionEvaluationRepository;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.Breakdown;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.HcadSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.Qualification;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.RecentEvaluation;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.ResourceBreakdown;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.UserSessionBreakdown;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;

public class HcadMonitoringService {

    private static final int BREAKDOWN_LIMIT = 12;
    private static final DateTimeFormatter ISO = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    private final HcadDetectionEvaluationRepository repository;
    private final HcadProperties hcadProperties;

    public HcadMonitoringService(
            HcadDetectionEvaluationRepository repository,
            HcadProperties hcadProperties) {
        this.repository = repository;
        this.hcadProperties = hcadProperties;
    }

    @Transactional(readOnly = true)
    public HcadSummary summarize(String period) {
        String normalizedPeriod = normalizePeriod(period);
        LocalDateTime to = LocalDateTime.now();
        LocalDateTime from = switch (normalizedPeriod) {
            case "week" -> to.minusWeeks(1);
            case "month" -> to.minusMonths(1);
            case "year" -> to.minusYears(1);
            default -> to.minusDays(1);
        };

        long candidateCount = repository.countByCreatedAtBetween(from, to);
        long observedRequestCount = longValue(repository.sumRequestCountBetween(from, to));
        long triggeredLlmCount = repository.countByTriggeredLlmTrueAndCreatedAtBetween(from, to);
        long duplicateSuppressedCount = longValue(repository.sumDuplicateSuppressedCountBetween(from, to));
        long tp = repository.countByOutcomeClassAndCreatedAtBetween("TP", from, to);
        long fp = repository.countByOutcomeClassAndCreatedAtBetween("FP", from, to);
        long fn = repository.countByOutcomeClassAndCreatedAtBetween("FN", from, to);
        long tn = repository.countByOutcomeClassAndCreatedAtBetween("TN", from, to);
        long unknown = repository.countByOutcomeClassAndCreatedAtBetween("UNKNOWN", from, to);
        double precision = precision(tp, fp);
        double unknownRate = ratio(unknown, candidateCount);
        double averageLatency = doubleValue(repository.averageLlmLatencyMsBetween(from, to));

        HcadProperties.PreTriggerSettings.QualificationSettings q =
                hcadProperties.getPreTrigger().getQualification();
        double estimatedWasteCost = fp * q.getEstimatedLlmCallCostUsd();

        return new HcadSummary(
                normalizedPeriod,
                ISO.format(from),
                ISO.format(to),
                hcadProperties.getPreTrigger().effectiveMode().metadataValue(),
                candidateCount,
                observedRequestCount,
                triggeredLlmCount,
                tp,
                fp,
                fn,
                tn,
                unknown,
                duplicateSuppressedCount,
                precision,
                unknownRate,
                averageLatency,
                fp,
                estimatedWasteCost,
                new Qualification(
                        q.getShadowMinPrecision(),
                        q.getLimitedEnforceMinPrecision(),
                        q.getDefaultEnforceMinPrecision(),
                        q.getMinimumSampleSize(),
                        q.getEstimatedLlmCallCostUsd()),
                recommendation(candidateCount, precision, q),
                modeBreakdown(from, to),
                signalBreakdown(from, to),
                resourceBreakdown(from, to),
                userSessionBreakdown(from, to),
                recentEvaluations(from, to),
                unknownEvaluations(from, to));
    }

    @Transactional(readOnly = true)
    public String exportCsv(String period) {
        HcadSummary summary = summarize(period);
        StringBuilder csv = new StringBuilder();
        csv.append("period,from,to,currentMode,candidates,observedRequests,llmCalls,precision,falsePositive,observableFalseNegative,unknown,duplicates,averageLatencyMs,wasteCostUsd,recommendation\n");
        csv.append(csv(summary.period())).append(',')
                .append(csv(summary.from())).append(',')
                .append(csv(summary.to())).append(',')
                .append(csv(summary.currentMode())).append(',')
                .append(summary.candidateCount()).append(',')
                .append(summary.observedRequestCount()).append(',')
                .append(summary.triggeredLlmCount()).append(',')
                .append(summary.precision()).append(',')
                .append(summary.falsePositiveCount()).append(',')
                .append(summary.observableFalseNegativeCount()).append(',')
                .append(summary.unknownCount()).append(',')
                .append(summary.duplicateSuppressedCount()).append(',')
                .append(summary.averageLlmLatencyMs()).append(',')
                .append(summary.estimatedWasteCostUsd()).append(',')
                .append(csv(summary.recommendation())).append('\n');
        csv.append('\n');
        csv.append("createdAt,userId,method,path,score,band,triggeredLlm,duplicateSuppressed,llmAction,llmRiskScore,llmConfidence,parserFailure,technicalFallback,fallbackCategory,outcome\n");
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
        return repository.countByModeBetween(from, to).stream()
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

    private List<RecentEvaluation> recentEvaluations(LocalDateTime from, LocalDateTime to) {
        return repository.findTop50ByCreatedAtBetweenOrderByCreatedAtDesc(from, to).stream()
                .map(this::toRecentEvaluation)
                .toList();
    }

    private List<RecentEvaluation> unknownEvaluations(LocalDateTime from, LocalDateTime to) {
        return repository.findTop25ByOutcomeClassAndCreatedAtBetweenOrderByCreatedAtDesc("UNKNOWN", from, to).stream()
                .map(this::toRecentEvaluation)
                .toList();
    }

    private RecentEvaluation toRecentEvaluation(HcadDetectionEvaluation evaluation) {
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
                format(evaluation.getCreatedAt()),
                format(evaluation.getDecidedAt()));
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
}
