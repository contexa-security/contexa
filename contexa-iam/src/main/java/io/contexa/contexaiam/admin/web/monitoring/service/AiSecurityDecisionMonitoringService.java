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

import io.contexa.contexacore.properties.HcadProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.hcad.trigger.HcadPreTriggerMode;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.CorrelationMatrixRow;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.CorrelationSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.AffectedRequest;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.FailureSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.LlmDecisionSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.MetricValue;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.MonitorSnapshot;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.NamedCount;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.OperationsSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.OverviewSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.RecentFailure;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.RecentCorrelation;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.ReadinessSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.RuntimeModeSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.StandardMetrics;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.HcadSummary;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class AiSecurityDecisionMonitoringService {

    private static final DateTimeFormatter ISO = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
    private static final int BREAKDOWN_LIMIT = 12;
    private static final String MONITORABLE_PATH_CONDITION = """
            not (
                lower(coalesce(@PATH@, '')) in (
                    '/favicon.ico',
                    '/manifest.json',
                    '/manifest.webmanifest',
                    '/robots.txt',
                    '/login',
                    '/logout',
                    '/admin/login',
                    '/admin/logout',
                    '/contexa/admin/login',
                    '/contexa/admin/logout',
                    '/mfa/login',
                    '/contexa/mfa/login'
                )
                or lower(coalesce(@PATH@, '')) like '/assets/%'
                or lower(coalesce(@PATH@, '')) like '/css/%'
                or lower(coalesce(@PATH@, '')) like '/fonts/%'
                or lower(coalesce(@PATH@, '')) like '/img/%'
                or lower(coalesce(@PATH@, '')) like '/images/%'
                or lower(coalesce(@PATH@, '')) like '/static/%'
                or lower(coalesce(@PATH@, '')) like '/webjars/%'
                or lower(coalesce(@PATH@, '')) like '/.well-known/appspecific/%'
                or lower(coalesce(@PATH@, '')) like '%.avif'
                or lower(coalesce(@PATH@, '')) like '%.css'
                or lower(coalesce(@PATH@, '')) like '%.eot'
                or lower(coalesce(@PATH@, '')) like '%.gif'
                or lower(coalesce(@PATH@, '')) like '%.ico'
                or lower(coalesce(@PATH@, '')) like '%.jpeg'
                or lower(coalesce(@PATH@, '')) like '%.jpg'
                or lower(coalesce(@PATH@, '')) like '%.js'
                or lower(coalesce(@PATH@, '')) like '%.map'
                or lower(coalesce(@PATH@, '')) like '%.mjs'
                or lower(coalesce(@PATH@, '')) like '%.otf'
                or lower(coalesce(@PATH@, '')) like '%.png'
                or lower(coalesce(@PATH@, '')) like '%.svg'
                or lower(coalesce(@PATH@, '')) like '%.ttf'
                or lower(coalesce(@PATH@, '')) like '%.webp'
                or lower(coalesce(@PATH@, '')) like '%.woff'
                or lower(coalesce(@PATH@, '')) like '%.woff2'
            )
            """;

    private final HcadMonitoringService hcadMonitoringService;
    private final Supplier<JdbcOperations> jdbcOperationsSupplier;
    private final HcadProperties hcadProperties;
    private final SecurityZeroTrustProperties zeroTrustProperties;

    public AiSecurityDecisionMonitoringService(
            HcadMonitoringService hcadMonitoringService,
            Supplier<JdbcOperations> jdbcOperationsSupplier,
            HcadProperties hcadProperties,
            SecurityZeroTrustProperties zeroTrustProperties) {
        this.hcadMonitoringService = hcadMonitoringService;
        this.jdbcOperationsSupplier = jdbcOperationsSupplier == null ? () -> null : jdbcOperationsSupplier;
        this.hcadProperties = hcadProperties;
        this.zeroTrustProperties = zeroTrustProperties;
    }

    @Transactional(readOnly = true)
    public OverviewSummary overview(String period) {
        SnapshotData data = snapshotData(period);
        return new OverviewSummary(
                data.window().period(),
                ISO.format(data.window().from()),
                ISO.format(data.window().to()),
                data.snapshot().generatedAt(),
                data.snapshot(),
                data.metrics(),
                data.hcad(),
                withMetrics(data.llm(), data.snapshot(), data.metrics()),
                withMetrics(data.correlation(), data.snapshot(), data.metrics()),
                data.operations(),
                data.readinessRecommendation());
    }

    @Transactional(readOnly = true)
    public LlmDecisionSummary llm(String period) {
        SnapshotData data = snapshotData(period);
        return withMetrics(data.llm(), data.snapshot(), data.metrics());
    }

    @Transactional(readOnly = true)
    public CorrelationSummary correlation(String period) {
        SnapshotData data = snapshotData(period);
        return withMetrics(data.correlation(), data.snapshot(), data.metrics());
    }

    @Transactional(readOnly = true)
    public FailureSummary failures(String period) {
        SnapshotData data = snapshotData(period);
        TimeWindow window = data.window();
        List<NamedCount> canonicalFailures = explicitFailureBreakdown(window.from(), window.to());
        return new FailureSummary(
                window.period(),
                ISO.format(window.from()),
                ISO.format(window.to()),
                data.snapshot().generatedAt(),
                data.snapshot(),
                data.metrics(),
                data.operations(),
                canonicalFailures,
                canonicalFailures,
                nonEmptyBreakdown("fallback_category", window.from(), window.to()),
                breakdown("ai_security_decision_observation", "coalesce(model_provider, 'UNKNOWN')", window.from(), window.to()),
                breakdown("ai_security_decision_observation", "coalesce(model_id, 'UNKNOWN')", window.from(), window.to()),
                breakdown("ai_security_decision_observation", "coalesce(prompt_template_key, 'UNKNOWN')", window.from(), window.to()),
                failureTrend(window.period(), window.from(), window.to()),
                affectedRequests(window.from(), window.to()),
                recentFailures(window.from(), window.to()),
                slowRequests(window.from(), window.to()));
    }

    @Transactional(readOnly = true)
    public ReadinessSummary readiness(String period) {
        SnapshotData data = snapshotData(period);
        HcadSummary hcad = data.hcad();
        LlmDecisionSummary llm = data.llm();
        OperationsSummary operations = data.operations();
        return new ReadinessSummary(
                data.window().period(),
                ISO.format(data.window().from()),
                ISO.format(data.window().to()),
                data.snapshot().generatedAt(),
                data.snapshot(),
                data.metrics(),
                data.readinessRecommendation(),
                hcad.qualification().minimumSampleSize(),
                hcad.candidateCount(),
                llm.totalDecisionCount(),
                metricNumber(data.metrics().hcadPrecision()),
                metricNumber(data.metrics().observableFalseNegativeRate()),
                metricNumber(data.metrics().unknownRate()),
                metricNumber(data.metrics().failureRate()),
                llm.parserFailureRate(),
                llm.technicalFallbackRate(),
                llm.timeoutRate(),
                llm.modelUnavailableRate(),
                operations.averageLatencyMs(),
                p95Latency(data.window().from(), data.window().to()),
                operations.estimatedWasteCostUsd(),
                operations.estimatedSavedCostUsd());
    }

    @Transactional(readOnly = true)
    public String exportCsv(String period, String type, Locale locale) {
        String normalizedType = type == null || type.isBlank()
                ? "overview"
                : type.trim().toLowerCase(Locale.ROOT);
        boolean korean = locale != null && "ko".equalsIgnoreCase(locale.getLanguage());
        return switch (normalizedType) {
            case "llm" -> {
                LlmDecisionSummary summary = llm(period);
                yield csv(List.of(
                        row(label(korean, "\uD56D\uBAA9", "Metric"), label(korean, "\uAC12", "Value")),
                        row(label(korean, "\uC804\uCCB4 LLM \uD310\uC815", "Total LLM decisions"),
                                summary.totalDecisionCount()),
                        row(label(korean, "HCAD \uC120\uD589 \uD2B8\uB9AC\uAC70 \uD310\uC815",
                                "HCAD pre-trigger decisions"), summary.hcadPreTriggerDecisionCount()),
                        row(label(korean, "Protectable \uD310\uC815", "Protectable decisions"),
                                summary.protectableDecisionCount())));
            }
            case "correlation" -> {
                CorrelationSummary summary = correlation(period);
                yield csv(List.of(
                        row(label(korean, "\uD56D\uBAA9", "Metric"), label(korean, "\uAC12", "Value")),
                        row(label(korean, "\uC815\uD0D0(TP)", "True positive (TP)"),
                                summary.truePositiveCount()),
                        row(label(korean, "\uC624\uD0D0(FP)", "False positive (FP)"),
                                summary.falsePositiveCount()),
                        row(label(korean, "\uAD00\uCE21 \uAC00\uB2A5 \uBBF8\uD0D0(FN)",
                                "Observable false negative (FN)"), summary.observableFalseNegativeCount()),
                        row(label(korean, "\uC815\uC0C1 \uD310\uC815(TN)", "True negative (TN)"),
                                summary.trueNegativeCount()),
                        row(label(korean, "\uBD88\uBA85\uD655", "Unknown"), summary.unknownCount())));
            }
            case "failures" -> {
                FailureSummary summary = failures(period);
                yield csv(List.of(
                        row(label(korean, "\uD56D\uBAA9", "Metric"), label(korean, "\uAC12", "Value")),
                        row(label(korean, "\uD30C\uC11C \uC2E4\uD328", "Parser failures"),
                                summary.operations().parserFailureCount()),
                        row(label(korean, "\uAE30\uC220 \uB300\uCCB4 \uCC98\uB9AC", "Technical fallbacks"),
                                summary.operations().technicalFallbackCount()),
                        row(label(korean, "\uC2DC\uAC04 \uCD08\uACFC", "Timeouts"),
                                summary.operations().timeoutCount()),
                        row(label(korean, "\uBAA8\uB378 \uC0AC\uC6A9 \uBD88\uAC00", "Model unavailable"),
                                summary.operations().modelUnavailableCount())));
            }
            case "readiness" -> {
                ReadinessSummary summary = readiness(period);
                yield csv(List.of(
                        row(label(korean, "\uD56D\uBAA9", "Metric"), label(korean, "\uAC12", "Value")),
                        row(label(korean, "\uC804\uD658 \uAD8C\uC7A5 \uC0C1\uD0DC",
                                "Readiness recommendation"), summary.recommendation()),
                        row(label(korean, "\uCD5C\uC18C \uD45C\uBCF8 \uC218", "Minimum sample size"),
                                summary.minimumSampleSize()),
                        row(label(korean, "HCAD \uC815\uBC00\uB3C4", "HCAD precision"),
                                summary.hcadPrecision()),
                        row(label(korean, "\uBD88\uBA85\uD655 \uBE44\uC728", "Unknown rate"),
                                summary.unknownRate()),
                        row(label(korean, "\uC2E4\uD328 \uBE44\uC728", "Failure rate"),
                                summary.failureRate())));
            }
            default -> {
                OverviewSummary summary = overview(period);
                yield csv(List.of(
                        row(label(korean, "\uD56D\uBAA9", "Metric"), label(korean, "\uAC12", "Value")),
                        row(label(korean, "HCAD \uD3C9\uAC00", "HCAD candidates"),
                                summary.hcad().candidateCount()),
                        row(label(korean, "LLM \uD310\uC815", "LLM decisions"),
                                summary.llm().totalDecisionCount()),
                        row(label(korean, "\uBD88\uBA85\uD655", "Unknown"),
                                summary.correlation().unknownCount()),
                        row(label(korean, "\uC2DC\uAC04 \uCD08\uACFC", "Timeouts"),
                                summary.operations().timeoutCount()),
                        row(label(korean, "\uC804\uD658 \uAD8C\uC7A5 \uC0C1\uD0DC",
                                "Readiness recommendation"), summary.readinessRecommendation())));
            }
        };
    }

    private SnapshotData snapshotData(String period) {
        TimeWindow window = window(period);
        MonitorSnapshot snapshot = new MonitorSnapshot(
                window.period(),
                ISO.format(window.from()),
                ISO.format(window.to()),
                ISO.format(window.generatedAt()),
                runtimeModeSummary());
        HcadSummary hcad = hcadMonitoringService.summarize(window.period(), window.from(), window.to());
        LlmDecisionSummary llm = llmSummary(window.from(), window.to());
        CorrelationSummary correlation = correlationSummary(window.from(), window.to());
        OperationsSummary operations = operationsSummary(window.from(), window.to(), hcad);
        StandardMetrics metrics = standardMetrics(hcad, llm, correlation, operations);
        return new SnapshotData(
                window,
                snapshot,
                hcad,
                llm,
                correlation,
                operations,
                metrics,
                readinessRecommendation(hcad, llm, correlation, operations));
    }

    private StandardMetrics standardMetrics(
            HcadSummary hcad,
            LlmDecisionSummary llm,
            CorrelationSummary correlation,
            OperationsSummary operations) {
        long tp = correlation.truePositiveCount();
        long fp = correlation.falsePositiveCount();
        long fn = correlation.observableFalseNegativeCount();
        long tn = correlation.trueNegativeCount();
        long unknown = correlation.unknownCount();
        long classified = tp + fp + fn + tn;
        long comparisonTotal = classified + unknown;
        long failures = operations.parserFailureCount()
                + operations.technicalFallbackCount()
                + operations.timeoutCount()
                + operations.modelUnavailableCount();
        return new StandardMetrics(
                countMetric("observedRequests", "전체 관측 요청", "기간 내 보안 판단 가치가 있는 요청 수입니다.",
                        hcad.observedRequestCount()),
                countMetric("hcadEvaluations", "조기탐지 평가", "HCAD가 실제 평가한 요청 또는 window 수입니다.",
                        hcad.candidateCount()),
                countMetric("hcadAiConnected", "조기탐지 AI 연결", "조기탐지 판단으로 AI 분석까지 이어진 수입니다.",
                        hcad.triggeredLlmCount()),
                countMetric("totalAiDecisions", "전체 AI 판정", "AI가 실제 분석한 요청 수입니다.",
                        llm.totalDecisionCount()),
                countMetric("clearOutcomes", "판정 확정", "정탐, 오탐, 미탐, 정상으로 비교 가능한 판정 수입니다.",
                        classified),
                ratioMetric("hcadPrecision", "HCAD 정탐 비율", "조기탐지가 위험으로 본 요청 중 AI도 위험으로 본 비율입니다.",
                        tp, tp + fp, "NO_HCAD_RISK_COMPARISON"),
                ratioMetric("matchRate", "판정 일치율", "조기탐지와 AI가 같은 방향으로 판단한 비율입니다.",
                        tp + tn, classified, "NO_CLASSIFIED_COMPARISON"),
                ratioMetric("mismatchRate", "판정 불일치율", "조기탐지와 AI 판단이 충돌한 비율입니다.",
                        fp + fn, classified, "NO_CLASSIFIED_COMPARISON"),
                ratioMetric("falsePositiveRate", "오탐률", "조기탐지가 위험으로 봤지만 AI가 허용한 비율입니다.",
                        fp, tp + fp, "NO_HCAD_RISK_COMPARISON"),
                ratioMetric("observableFalseNegativeRate", "미탐률", "조기탐지가 놓쳤지만 AI가 위험으로 본 비율입니다.",
                        fn, tp + fn, "NO_AI_RISK_COMPARISON"),
                ratioMetric("unknownRate", "판정 불명확 비율", "비교 또는 판정 신뢰가 어려운 비율입니다.",
                        unknown, comparisonTotal, "NO_COMPARISON_DATA"),
                ratioMetric("failureRate", "AI 분석 실패율", "AI 분석 자체가 정상 완료되지 않은 비율입니다.",
                        failures, llm.totalDecisionCount(), "NO_AI_DECISION_DATA"),
                ratioMetric("timeoutRate", "시간 초과율", "AI 분석 요청 중 시간 초과된 비율입니다.",
                        operations.timeoutCount(), llm.totalDecisionCount(), "NO_AI_DECISION_DATA"),
                durationMetric("averageLatencyMs", "평균 분석 지연", "AI 분석 응답 평균 시간입니다.",
                        operations.averageLatencyMs(), llm.totalDecisionCount()));
    }

    private MetricValue countMetric(String key, String label, String description, long value) {
        return new MetricValue(key, label, description, (double) value, value, null, "COUNT", null);
    }

    private MetricValue ratioMetric(
            String key,
            String label,
            String description,
            long numerator,
            long denominator,
            String noDataReason) {
        return new MetricValue(
                key,
                label,
                description,
                denominator <= 0 ? null : (double) numerator / denominator,
                numerator,
                denominator,
                "RATIO",
                denominator <= 0 ? noDataReason : null);
    }

    private MetricValue durationMetric(
            String key,
            String label,
            String description,
            double value,
            long denominator) {
        return new MetricValue(
                key,
                label,
                description,
                denominator <= 0 ? null : value,
                null,
                denominator,
                "MILLISECONDS",
                denominator <= 0 ? "NO_AI_DECISION_DATA" : null);
    }

    private LlmDecisionSummary withMetrics(
            LlmDecisionSummary summary,
            MonitorSnapshot snapshot,
            StandardMetrics metrics) {
        return new LlmDecisionSummary(
                snapshot,
                metrics,
                summary.totalDecisionCount(),
                summary.hcadPreTriggerDecisionCount(),
                summary.protectableDecisionCount(),
                summary.hcadAndProtectableDecisionCount(),
                summary.triggerSourceBreakdown(),
                summary.actionBreakdown(),
                summary.proposedActionBreakdown(),
                summary.finalActionBreakdown(),
                summary.providerBreakdown(),
                summary.modelBreakdown(),
                summary.promptTemplateBreakdown(),
                summary.parserFailureCount(),
                summary.technicalFallbackCount(),
                summary.timeoutCount(),
                summary.modelUnavailableCount(),
                summary.parserFailureRate(),
                summary.technicalFallbackRate(),
                summary.timeoutRate(),
                summary.modelUnavailableRate(),
                summary.averageLatencyMs(),
                summary.p95LatencyMs(),
                summary.riskScoreDistribution(),
                summary.confidenceDistribution());
    }

    private CorrelationSummary withMetrics(
            CorrelationSummary summary,
            MonitorSnapshot snapshot,
            StandardMetrics metrics) {
        return new CorrelationSummary(
                snapshot,
                metrics,
                summary.truePositiveCount(),
                summary.falsePositiveCount(),
                summary.observableFalseNegativeCount(),
                summary.trueNegativeCount(),
                summary.unknownCount(),
                summary.unobservedCount(),
                summary.triggerRelationBreakdown(),
                summary.outcomeBreakdown(),
                summary.matrixRows(),
                summary.notCalledReasonBreakdown(),
                summary.recentCorrelations());
    }

    private double metricNumber(MetricValue metric) {
        return metric == null || metric.value() == null ? 0.0d : metric.value();
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

    private LlmDecisionSummary llmSummary(LocalDateTime from, LocalDateTime to) {
        long total = countAi("created_at between ? and ?", from, to);
        long parserFailures = countAi(
                "parser_failure = true and created_at between ? and ?", from, to);
        long technicalFallbacks = countAi(
                "technical_fallback = true and created_at between ? and ?", from, to);
        long timeouts = countAi(
                "timeout_failure = true and created_at between ? and ?", from, to);
        long modelUnavailable = countAi(
                "model_unavailable = true and created_at between ? and ?", from, to);
        return new LlmDecisionSummary(
                null,
                null,
                total,
                countAi(
                        "trigger_relation in ('HCAD_ONLY', 'HCAD_AND_PROTECTABLE') and created_at between ? and ?",
                        from,
                        to),
                countAi(
                        "trigger_relation in ('PROTECTABLE_ONLY', 'HCAD_AND_PROTECTABLE') and created_at between ? and ?",
                        from,
                        to),
                countAi(
                        "trigger_relation = 'HCAD_AND_PROTECTABLE' and created_at between ? and ?",
                        from,
                        to),
                breakdownAi("trigger_source", from, to),
                breakdownAi("coalesce(final_action, 'UNKNOWN')", from, to),
                breakdownAi("coalesce(proposed_action, 'UNKNOWN')", from, to),
                breakdownAi("coalesce(final_action, 'UNKNOWN')", from, to),
                breakdownAi("coalesce(model_provider, 'UNKNOWN')", from, to),
                breakdownAi("coalesce(model_id, 'UNKNOWN')", from, to),
                breakdownAi("coalesce(prompt_template_key, 'UNKNOWN')", from, to),
                parserFailures,
                technicalFallbacks,
                timeouts,
                modelUnavailable,
                ratio(parserFailures, total),
                ratio(technicalFallbacks, total),
                ratio(timeouts, total),
                ratio(modelUnavailable, total),
                averageAi("llm_latency_ms", from, to),
                p95Latency(from, to),
                numericBucketBreakdownAi("llm_risk_score", from, to),
                numericBucketBreakdownAi("llm_confidence", from, to));
    }

    private CorrelationSummary correlationSummary(LocalDateTime from, LocalDateTime to) {
        return new CorrelationSummary(
                null,
                null,
                countCorrelationOutcome("TP", from, to),
                countCorrelationOutcome("FP", from, to),
                countCorrelationOutcome("FN", from, to),
                countCorrelationOutcome("TN", from, to),
                countCorrelationOutcome("UNKNOWN", from, to),
                countCorrelationOutcome("UNOBSERVED", from, to),
                breakdownCorrelation("c.trigger_relation", from, to),
                breakdownCorrelation("c.outcome_class", from, to),
                correlationMatrix(from, to),
                notCalledReasonBreakdown(from, to),
                recentCorrelations(from, to));
    }

    private OperationsSummary operationsSummary(LocalDateTime from, LocalDateTime to, HcadSummary hcad) {
        double cost = hcadProperties.getPreTrigger().getQualification().getEstimatedLlmCallCostUsd();
        long parserFailures = countAi(
                "parser_failure = true and created_at between ? and ?", from, to);
        long technicalFallbacks = countAi(
                "technical_fallback = true and created_at between ? and ?", from, to);
        long timeouts = countAi(
                "timeout_failure = true and created_at between ? and ?", from, to);
        long modelUnavailable = countAi(
                "model_unavailable = true and created_at between ? and ?", from, to);
        return new OperationsSummary(
                averageAi("llm_latency_ms", from, to),
                parserFailures,
                technicalFallbacks,
                timeouts,
                modelUnavailable,
                hcad.falsePositiveCount(),
                hcad.falsePositiveCount() * cost,
                hcad.duplicateSuppressedCount() * cost);
    }

    private List<NamedCount> explicitFailureBreakdown(LocalDateTime from, LocalDateTime to) {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return List.of();
        }
        String sql = """
                select metric_key, count(*) as failure_count
                  from (
                        select %s as metric_key
                          from ai_security_decision_observation
                         where created_at between ? and ?
                           and %s
                       ) failure_causes
                 where metric_key is not null
                 group by metric_key
                 order by failure_count desc, metric_key asc
                 limit ?
                """.formatted(canonicalFailureTypeExpression(), monitorablePath("request_path"));
        return jdbcOperations.query(
                sql,
                (rs, rowNum) -> new NamedCount(rs.getString("metric_key"), rs.getLong("failure_count")),
                from,
                to,
                BREAKDOWN_LIMIT);
    }

    private List<NamedCount> nonEmptyBreakdown(String columnName, LocalDateTime from, LocalDateTime to) {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return List.of();
        }
        String expression = "coalesce(" + columnName + ", '')";
        String sql = """
                select %1$s as metric_key, count(*) as count
                 from ai_security_decision_observation
                 where created_at between ? and ?
                   and (%2$s)
                   and %1$s <> ''
                   and upper(%1$s) not in ('NONE', 'UNKNOWN')
                   and %3$s
                 group by %1$s
                 order by count(*) desc, %1$s asc
                 limit ?
                """.formatted(expression, failurePredicate(), monitorablePath("request_path"));
        return jdbcOperations.query(
                sql,
                (rs, rowNum) -> new NamedCount(rs.getString("metric_key"), rs.getLong("count")),
                from,
                to,
                BREAKDOWN_LIMIT);
    }

    private List<NamedCount> failureTrend(String period, LocalDateTime from, LocalDateTime to) {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return List.of();
        }
        List<LocalDateTime> createdTimes = jdbcOperations.query("""
                        select created_at
                         from ai_security_decision_observation
                         where created_at between ? and ?
                           and (%s)
                           and %s
                         order by created_at asc
                        """.formatted(failurePredicate(), monitorablePath("request_path")),
                (rs, rowNum) -> rs.getObject("created_at", LocalDateTime.class),
                from,
                to);
        if (createdTimes.isEmpty()) {
            return List.of();
        }
        boolean hourly = "day".equalsIgnoreCase(period);
        DateTimeFormatter bucketFormatter = hourly
                ? DateTimeFormatter.ofPattern("MM-dd HH:00")
                : DateTimeFormatter.ofPattern("MM-dd");
        Map<String, Long> buckets = new LinkedHashMap<>();
        for (LocalDateTime createdTime : createdTimes) {
            LocalDateTime normalized = hourly
                    ? createdTime.withMinute(0).withSecond(0).withNano(0)
                    : createdTime.toLocalDate().atStartOfDay();
            String key = bucketFormatter.format(normalized);
            buckets.put(key, buckets.getOrDefault(key, 0L) + 1L);
        }
        return buckets.entrySet().stream()
                .map(entry -> new NamedCount(entry.getKey(), entry.getValue()))
                .toList();
    }

    private List<AffectedRequest> affectedRequests(LocalDateTime from, LocalDateTime to) {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return List.of();
        }
        return jdbcOperations.query("""
                        select coalesce(http_method, '') as method,
                               coalesce(request_path, '-') as path,
                               count(*) as count
                          from ai_security_decision_observation
                         where created_at between ? and ?
                           and (%s)
                           and %s
                         group by coalesce(http_method, ''), coalesce(request_path, '-')
                         order by count(*) desc, path asc
                         limit 10
                        """.formatted(failurePredicate(), monitorablePath("request_path")),
                (rs, rowNum) -> new AffectedRequest(
                        rs.getString("method"),
                        rs.getString("path"),
                        rs.getLong("count")),
                from,
                to);
    }

    private List<RecentFailure> recentFailures(LocalDateTime from, LocalDateTime to) {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return List.of();
        }
        return jdbcOperations.query("""
                        select observation_id,
                               request_id,
                               user_id,
                               http_method,
                               request_path,
                               case
                                 when (%1$s) is not null then (%1$s)
                                 else 'UNKNOWN'
                               end as failure_type,
                               final_action,
                               llm_latency_ms,
                               created_at
                         from ai_security_decision_observation
                         where created_at between ? and ?
                           and (%2$s)
                           and %3$s
                         order by created_at desc
                         limit 10
                        """.formatted(canonicalFailureTypeExpression(), failurePredicate(), monitorablePath("request_path")),
                (rs, rowNum) -> {
                    Number latency = (Number) rs.getObject("llm_latency_ms");
                    return new RecentFailure(
                            rs.getString("observation_id"),
                            rs.getString("request_id"),
                            rs.getString("user_id"),
                            rs.getString("http_method"),
                            rs.getString("request_path"),
                            rs.getString("failure_type"),
                            rs.getString("final_action"),
                            latency == null ? null : latency.doubleValue(),
                            format(rs.getObject("created_at", LocalDateTime.class)));
                },
                from,
                to);
    }

    private List<RecentFailure> slowRequests(LocalDateTime from, LocalDateTime to) {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return List.of();
        }
        return jdbcOperations.query("""
                        select observation_id,
                               request_id,
                               user_id,
                               http_method,
                               request_path,
                               case
                                 when (%1$s) is not null then (%1$s)
                                 else 'SLOW_ANALYSIS'
                               end as failure_type,
                               final_action,
                               llm_latency_ms,
                               created_at
                         from ai_security_decision_observation
                        where created_at between ? and ?
                          and llm_latency_ms is not null
                          and %2$s
                        order by llm_latency_ms desc, created_at desc
                        limit 10
                        """.formatted(canonicalFailureTypeExpression(), monitorablePath("request_path")),
                (rs, rowNum) -> {
                    Number latency = (Number) rs.getObject("llm_latency_ms");
                    return new RecentFailure(
                            rs.getString("observation_id"),
                            rs.getString("request_id"),
                            rs.getString("user_id"),
                            rs.getString("http_method"),
                            rs.getString("request_path"),
                            rs.getString("failure_type"),
                            rs.getString("final_action"),
                            latency == null ? null : latency.doubleValue(),
                            format(rs.getObject("created_at", LocalDateTime.class)));
                },
                from,
                to);
    }

    private String failurePredicate() {
        return """
                parser_failure = true
                or technical_fallback = true
                or timeout_failure = true
                or model_unavailable = true
                or (failure_type is not null and failure_type <> '' and upper(failure_type) <> 'NONE')
                """;
    }

    private String canonicalFailureTypeExpression() {
        return """
                case
                  when timeout_failure = true or upper(coalesce(failure_type, '')) = 'TIMEOUT' then 'TIMEOUT'
                  when model_unavailable = true
                       or upper(coalesce(failure_type, '')) in ('MODEL_UNAVAILABLE', 'NO_RUNTIME_LLM_CLIENT', 'NO_PIPELINE_EXECUTOR')
                    then 'MODEL_UNAVAILABLE'
                  when parser_failure = true
                       or upper(coalesce(failure_type, '')) in (
                            'PARSER_FAILURE',
                            'PROMPT_CONTRACT_VIOLATION',
                            'MALFORMED_JSON',
                            'EMPTY_RESPONSE'
                       )
                    then 'PARSER_FAILURE'
                  when technical_fallback = true
                       or upper(coalesce(failure_type, '')) = 'TECHNICAL_FALLBACK'
                       or (fallback_category is not null and fallback_category <> '' and upper(fallback_category) <> 'NONE')
                    then 'TECHNICAL_FALLBACK'
                  else null
                end
                """;
    }

    private List<CorrelationMatrixRow> correlationMatrix(LocalDateTime from, LocalDateTime to) {
        MatrixCounts early = matrixCounts("""
                c.trigger_relation in ('HCAD_ONLY', 'HCAD_AND_PROTECTABLE')
                """, from, to);
        MatrixCounts missed = matrixCounts("""
                c.trigger_relation in ('PROTECTABLE_ONLY', 'OBSERVED_ONLY')
                """, from, to);
        MatrixCounts suppressed = matrixCounts("""
                c.trigger_relation in ('PROTECTABLE_SUPPRESSED_BY_HCAD', 'HCAD_SUPPRESSED_BY_PROTECTABLE')
                """, from, to);
        MatrixCounts unevaluated = matrixCounts("""
                c.trigger_relation = 'UNMATCHED_LLM'
                """, from, to);

        early = early.withNotCalled(countHcad(
                "eligible = true and triggered_llm = false and decided_at is null and created_at between ? and ?",
                from, to));
        missed = missed.withNotCalled(countHcad(
                "(eligible = false or eligible is null) and triggered_llm = false and duplicate_suppressed = false and decided_at is null and created_at between ? and ?",
                from, to));
        suppressed = suppressed.withNotCalled(countHcad(
                "(duplicate_suppressed = true or coalesce(duplicate_suppressed_count, 0) > 0) and decided_at is null and created_at between ? and ?",
                from, to));

        return List.of(
                new CorrelationMatrixRow("HCAD_EARLY_TRIGGER", early.risk(), early.allow(), early.unknown(), early.notCalled()),
                new CorrelationMatrixRow("HCAD_MISSED_OBSERVED", missed.risk(), missed.allow(), missed.unknown(), missed.notCalled()),
                new CorrelationMatrixRow("HCAD_DUPLICATE_SUPPRESSED", suppressed.risk(), suppressed.allow(), suppressed.unknown(), suppressed.notCalled()),
                new CorrelationMatrixRow("HCAD_UNEVALUATED", unevaluated.risk(), unevaluated.allow(), unevaluated.unknown(), unevaluated.notCalled()));
    }

    private List<NamedCount> notCalledReasonBreakdown(LocalDateTime from, LocalDateTime to) {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return List.of();
        }
        String sql = """
                        select reason_key, count(*) as reason_count
                          from (
                                select case
                                         when duplicate_suppressed = true
                                           or coalesce(duplicate_suppressed_count, 0) > 0
                                           then 'DUPLICATE_SUPPRESSED'
                                         when upper(coalesce(mode, '')) in ('OBSERVE', 'DISABLED')
                                           then 'POLICY_OBSERVE_ONLY'
                                         when reason_codes is not null
                                           and upper(reason_codes) like '%RATE_LIMIT%'
                                           then 'RATE_LIMITED'
                                         when eligible = false or eligible is null
                                           then 'LOW_RISK'
                                         else 'NOT_TRIGGERED'
                                       end as reason_key
                                 from hcad_detection_evaluation
                                 where created_at between ? and ?
                                   and triggered_llm = false
                                   and decided_at is null
                                   and @MONITORABLE@
                               ) reasons
                         group by reason_key
                         order by reason_count desc, reason_key asc
                         limit ?
                        """.replace("@MONITORABLE@", monitorablePath("request_path"));
        return jdbcOperations.query(
                sql,
                (rs, rowNum) -> new NamedCount(rs.getString("reason_key"), rs.getLong("reason_count")),
                from,
                to,
                BREAKDOWN_LIMIT);
    }

    private MatrixCounts matrixCounts(String relationClause, LocalDateTime from, LocalDateTime to) {
        return new MatrixCounts(
                countCorrelation(
                        relationClause + " and c.outcome_class in ('TP', 'FN') and c.created_at between ? and ?",
                        from, to),
                countCorrelation(
                        relationClause + " and c.outcome_class in ('FP', 'TN') and c.created_at between ? and ?",
                        from, to),
                countCorrelation(
                        relationClause + " and c.outcome_class = 'UNKNOWN' and c.created_at between ? and ?",
                        from, to),
                countCorrelation(
                        relationClause + " and c.outcome_class = 'UNOBSERVED' and c.created_at between ? and ?",
                        from, to));
    }

    private List<RecentCorrelation> recentCorrelations(LocalDateTime from, LocalDateTime to) {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return List.of();
        }
        return jdbcOperations.query("""
                        select c.correlation_id,
                               c.hcad_evaluation_id,
                               c.llm_observation_id,
                               c.event_id,
                               c.request_id,
                               c.user_id,
                               c.trigger_relation,
                               c.outcome_class,
                               c.hcad_score,
                               c.hcad_band,
                               c.hcad_eligible,
                               c.llm_final_action,
                               c.llm_proposed_action,
                               c.llm_risk_score,
                               c.llm_confidence,
                               c.created_at,
                               c.decided_at
                          from hcad_llm_decision_correlation c
                         where c.created_at between ? and ?
                           and %s
                         order by c.created_at desc
                         limit 50
                        """.formatted(correlationMonitorableCondition()),
                (rs, rowNum) -> new RecentCorrelation(
                        rs.getString("correlation_id"),
                        rs.getString("hcad_evaluation_id"),
                        rs.getString("llm_observation_id"),
                        rs.getString("event_id"),
                        rs.getString("request_id"),
                        rs.getString("user_id"),
                        rs.getString("trigger_relation"),
                        rs.getString("outcome_class"),
                        (Integer) rs.getObject("hcad_score"),
                        rs.getString("hcad_band"),
                        (Boolean) rs.getObject("hcad_eligible"),
                        rs.getString("llm_final_action"),
                        rs.getString("llm_proposed_action"),
                        (Double) rs.getObject("llm_risk_score"),
                        (Double) rs.getObject("llm_confidence"),
                        format(rs.getObject("created_at", LocalDateTime.class)),
                        format(rs.getObject("decided_at", LocalDateTime.class))),
                from,
                to);
    }

    private String readinessRecommendation(
            HcadSummary hcad,
            LlmDecisionSummary llm,
            CorrelationSummary correlation,
            OperationsSummary operations) {
        if (llm.totalDecisionCount() <= 0 || hcad.candidateCount() < hcad.qualification().minimumSampleSize()) {
            return "INSUFFICIENT_SAMPLE";
        }
        double failureRate = ratio(
                operations.parserFailureCount()
                        + operations.technicalFallbackCount()
                        + operations.timeoutCount()
                        + operations.modelUnavailableCount(),
                llm.totalDecisionCount());
        double observableFnRate = ratio(correlation.observableFalseNegativeCount(),
                correlation.truePositiveCount()
                        + correlation.observableFalseNegativeCount());
        if (failureRate >= 0.10d || observableFnRate >= 0.10d) {
            return "DO_NOT_ENFORCE";
        }
        if ("DEFAULT_ENFORCE_CANDIDATE".equals(hcad.recommendation())) {
            return "DEFAULT_ENFORCE_CANDIDATE";
        }
        if ("LIMITED_ENFORCE_CANDIDATE".equals(hcad.recommendation())) {
            return "LIMITED_ENFORCE_CANDIDATE";
        }
        if ("SHADOW_STABLE".equals(hcad.recommendation())) {
            return "SHADOW_STABLE";
        }
        return "KEEP_SHADOW";
    }

    private long countCorrelationOutcome(String outcome, LocalDateTime from, LocalDateTime to) {
        return countCorrelation("c.outcome_class = ? and c.created_at between ? and ?", outcome, from, to);
    }

    private long countAi(String whereClause, Object... args) {
        return count("ai_security_decision_observation", whereClause + " and " + monitorablePath("request_path"), args);
    }

    private long countHcad(String whereClause, Object... args) {
        return count("hcad_detection_evaluation", whereClause + " and " + monitorablePath("request_path"), args);
    }

    private long countCorrelation(String whereClause, Object... args) {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return 0L;
        }
        Long value = jdbcOperations.queryForObject(
                """
                        select count(*)
                          from hcad_llm_decision_correlation c
                         where %s
                           and %s
                        """.formatted(whereClause, correlationMonitorableCondition()),
                Long.class,
                args);
        return value == null ? 0L : value;
    }

    private List<NamedCount> breakdownAi(String expression, LocalDateTime from, LocalDateTime to) {
        return breakdownWhere(
                "ai_security_decision_observation",
                expression,
                "created_at between ? and ? and " + monitorablePath("request_path"),
                from,
                to);
    }

    private List<NamedCount> breakdownCorrelation(String expression, LocalDateTime from, LocalDateTime to) {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return List.of();
        }
        String sql = """
                select %s as metric_key, count(*) as count
                  from hcad_llm_decision_correlation c
                 where c.created_at between ? and ?
                   and %s
                 group by %s
                 order by count(*) desc, %s asc
                 limit ?
                """.formatted(expression, correlationMonitorableCondition(), expression, expression);
        return jdbcOperations.query(
                sql,
                (rs, rowNum) -> new NamedCount(rs.getString("metric_key"), rs.getLong("count")),
                from,
                to,
                BREAKDOWN_LIMIT);
    }

    private List<NamedCount> breakdownWhere(
            String tableName,
            String expression,
            String whereClause,
            Object... args) {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return List.of();
        }
        String sql = """
                select %s as metric_key, count(*) as count
                  from %s
                 where %s
                 group by %s
                 order by count(*) desc, %s asc
                 limit ?
                """.formatted(expression, tableName, whereClause, expression, expression);
        Object[] queryArgs = Arrays.copyOf(args, args.length + 1);
        queryArgs[args.length] = BREAKDOWN_LIMIT;
        return jdbcOperations.query(
                sql,
                (rs, rowNum) -> new NamedCount(rs.getString("metric_key"), rs.getLong("count")),
                queryArgs);
    }

    private List<NamedCount> breakdown(String tableName, String expression, LocalDateTime from, LocalDateTime to) {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return List.of();
        }
        String sql = """
                select %s as metric_key, count(*) as count
                  from %s
                 where created_at between ? and ?
                 group by %s
                 order by count(*) desc, %s asc
                 limit ?
                """.formatted(expression, tableName, expression, expression);
        return jdbcOperations.query(
                sql,
                (rs, rowNum) -> new NamedCount(rs.getString("metric_key"), rs.getLong("count")),
                from,
                to,
                BREAKDOWN_LIMIT);
    }

    private List<NamedCount> numericBucketBreakdown(
            String tableName,
            String columnName,
            LocalDateTime from,
            LocalDateTime to) {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return List.of();
        }
        String bucketExpression = """
                case
                  when %1$s is null then 'UNKNOWN'
                  when %1$s < 0.2 then '0.00-0.19'
                  when %1$s < 0.4 then '0.20-0.39'
                  when %1$s < 0.6 then '0.40-0.59'
                  when %1$s < 0.8 then '0.60-0.79'
                  else '0.80-1.00'
                end
                """.formatted(columnName);
        String sql = """
                select %s as metric_key, count(*) as count
                  from %s
                 where created_at between ? and ?
                 group by %s
                 order by metric_key asc
                """.formatted(bucketExpression, tableName, bucketExpression);
        return jdbcOperations.query(
                sql,
                (rs, rowNum) -> new NamedCount(rs.getString("metric_key"), rs.getLong("count")),
                from,
                to);
    }

    private List<NamedCount> numericBucketBreakdownAi(
            String columnName,
            LocalDateTime from,
            LocalDateTime to) {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return List.of();
        }
        String bucketExpression = """
                case
                  when %1$s is null then 'UNKNOWN'
                  when %1$s < 0.2 then '0.00-0.19'
                  when %1$s < 0.4 then '0.20-0.39'
                  when %1$s < 0.6 then '0.40-0.59'
                  when %1$s < 0.8 then '0.60-0.79'
                  else '0.80-1.00'
                end
                """.formatted(columnName);
        String sql = """
                select %s as metric_key, count(*) as count
                  from ai_security_decision_observation
                 where created_at between ? and ?
                   and %s
                 group by %s
                 order by metric_key asc
                """.formatted(bucketExpression, monitorablePath("request_path"), bucketExpression);
        return jdbcOperations.query(
                sql,
                (rs, rowNum) -> new NamedCount(rs.getString("metric_key"), rs.getLong("count")),
                from,
                to);
    }

    private long count(String tableName, String whereClause, Object... args) {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return 0L;
        }
        Long value = jdbcOperations.queryForObject(
                "select count(*) from " + tableName + " where " + whereClause,
                Long.class,
                args);
        return value == null ? 0L : value;
    }

    private double average(String tableName, String columnName, LocalDateTime from, LocalDateTime to) {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return 0.0d;
        }
        Double value = jdbcOperations.queryForObject(
                "select avg(" + columnName + ") from " + tableName
                        + " where created_at between ? and ? and " + columnName + " is not null",
                Double.class,
                from,
                to);
        return value == null ? 0.0d : value;
    }

    private double averageAi(String columnName, LocalDateTime from, LocalDateTime to) {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return 0.0d;
        }
        Double value = jdbcOperations.queryForObject(
                "select avg(" + columnName + ") from ai_security_decision_observation"
                        + " where created_at between ? and ? and " + columnName + " is not null"
                        + " and " + monitorablePath("request_path"),
                Double.class,
                from,
                to);
        return value == null ? 0.0d : value;
    }

    private double p95Latency(String from, String to) {
        return p95Latency(LocalDateTime.parse(from, ISO), LocalDateTime.parse(to, ISO));
    }

    private double p95Latency(LocalDateTime from, LocalDateTime to) {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return 0.0d;
        }
        Double value = jdbcOperations.queryForObject(
                """
                        select percentile_cont(0.95) within group (order by llm_latency_ms)
                          from ai_security_decision_observation
                         where created_at between ? and ?
                           and llm_latency_ms is not null
                           and %s
                        """.formatted(monitorablePath("request_path")),
                Double.class,
                from,
                to);
        return value == null ? 0.0d : value;
    }

    private String monitorablePath(String pathExpression) {
        return MONITORABLE_PATH_CONDITION.replace("@PATH@", pathExpression);
    }

    private String correlationMonitorableCondition() {
        return """
                (
                    exists (
                        select 1
                          from ai_security_decision_observation a
                         where a.observation_id = c.llm_observation_id
                           and %1$s
                    )
                    or exists (
                        select 1
                          from hcad_detection_evaluation h
                         where h.evaluation_id = c.hcad_evaluation_id
                           and %2$s
                    )
                )
                """.formatted(monitorablePath("a.request_path"), monitorablePath("h.request_path"));
    }

    private String format(LocalDateTime value) {
        return value == null ? null : ISO.format(value);
    }

    private JdbcOperations jdbcOperations() {
        return jdbcOperationsSupplier == null ? null : jdbcOperationsSupplier.get();
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

    private LocalDateTime from(String period, LocalDateTime to) {
        return switch (period) {
            case "week" -> to.minusWeeks(1);
            case "month" -> to.minusMonths(1);
            case "year" -> to.minusYears(1);
            default -> to.minusDays(1);
        };
    }

    private TimeWindow window(String period) {
        String normalizedPeriod = normalizePeriod(period);
        LocalDateTime generatedAt = LocalDateTime.now().withNano(0);
        return new TimeWindow(normalizedPeriod, from(normalizedPeriod, generatedAt), generatedAt, generatedAt);
    }

    private double ratio(long numerator, long denominator) {
        return denominator <= 0 ? 0.0d : (double) numerator / denominator;
    }

    private String label(boolean korean, String ko, String en) {
        return korean ? ko : en;
    }

    private List<String> row(Object... values) {
        return Arrays.stream(values)
                .map(value -> value == null ? "" : value.toString())
                .toList();
    }

    private String csv(List<List<String>> rows) {
        return rows.stream()
                .map(row -> row.stream().map(this::escapeCsv).collect(Collectors.joining(",")))
                .collect(Collectors.joining("\n")) + "\n";
    }

    private String escapeCsv(String value) {
        String escaped = value.replace("\"", "\"\"");
        return "\"" + escaped + "\"";
    }

    private record TimeWindow(String period, LocalDateTime from, LocalDateTime to, LocalDateTime generatedAt) {
    }

    private record SnapshotData(
            TimeWindow window,
            MonitorSnapshot snapshot,
            HcadSummary hcad,
            LlmDecisionSummary llm,
            CorrelationSummary correlation,
            OperationsSummary operations,
            StandardMetrics metrics,
            String readinessRecommendation) {
    }

    private record MatrixCounts(long risk, long allow, long unknown, long notCalled) {
        private MatrixCounts withNotCalled(long additionalNotCalled) {
            return new MatrixCounts(risk, allow, unknown, notCalled + additionalNotCalled);
        }
    }
}
