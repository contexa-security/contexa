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
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.CorrelationMatrixRow;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.CorrelationSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.FailureSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.LlmDecisionSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.NamedCount;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.OperationsSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.OverviewSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.RecentCorrelation;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.ReadinessSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.HcadSummary;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class AiSecurityDecisionMonitoringService {

    private static final DateTimeFormatter ISO = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
    private static final int BREAKDOWN_LIMIT = 12;

    private final HcadMonitoringService hcadMonitoringService;
    private final Supplier<JdbcOperations> jdbcOperationsSupplier;
    private final HcadProperties hcadProperties;

    public AiSecurityDecisionMonitoringService(
            HcadMonitoringService hcadMonitoringService,
            Supplier<JdbcOperations> jdbcOperationsSupplier,
            HcadProperties hcadProperties) {
        this.hcadMonitoringService = hcadMonitoringService;
        this.jdbcOperationsSupplier = jdbcOperationsSupplier == null ? () -> null : jdbcOperationsSupplier;
        this.hcadProperties = hcadProperties;
    }

    @Transactional(readOnly = true)
    public OverviewSummary overview(String period) {
        String normalizedPeriod = normalizePeriod(period);
        LocalDateTime to = LocalDateTime.now();
        LocalDateTime from = from(normalizedPeriod, to);
        HcadSummary hcad = hcadMonitoringService.summarize(normalizedPeriod);
        LlmDecisionSummary llm = llmSummary(from, to);
        CorrelationSummary correlation = correlationSummary(from, to);
        OperationsSummary operations = operationsSummary(from, to, hcad);
        return new OverviewSummary(
                normalizedPeriod,
                ISO.format(from),
                ISO.format(to),
                hcad,
                llm,
                correlation,
                operations,
                readinessRecommendation(hcad, llm, correlation, operations));
    }

    @Transactional(readOnly = true)
    public LlmDecisionSummary llm(String period) {
        TimeWindow window = window(period);
        return llmSummary(window.from(), window.to());
    }

    @Transactional(readOnly = true)
    public CorrelationSummary correlation(String period) {
        TimeWindow window = window(period);
        return correlationSummary(window.from(), window.to());
    }

    @Transactional(readOnly = true)
    public FailureSummary failures(String period) {
        TimeWindow window = window(period);
        HcadSummary hcad = hcadMonitoringService.summarize(window.period());
        OperationsSummary operations = operationsSummary(window.from(), window.to(), hcad);
        return new FailureSummary(
                window.period(),
                ISO.format(window.from()),
                ISO.format(window.to()),
                operations,
                explicitFailureBreakdown(window.from(), window.to()),
                breakdown("ai_security_decision_observation", "coalesce(failure_type, 'NONE')", window.from(), window.to()),
                breakdown("ai_security_decision_observation", "coalesce(fallback_category, 'NONE')", window.from(), window.to()),
                breakdown("ai_security_decision_observation", "coalesce(model_provider, 'UNKNOWN')", window.from(), window.to()),
                breakdown("ai_security_decision_observation", "coalesce(model_id, 'UNKNOWN')", window.from(), window.to()),
                breakdown("ai_security_decision_observation", "coalesce(prompt_template_key, 'UNKNOWN')", window.from(), window.to()));
    }

    @Transactional(readOnly = true)
    public ReadinessSummary readiness(String period) {
        OverviewSummary overview = overview(period);
        long classified = overview.correlation().truePositiveCount()
                + overview.correlation().falsePositiveCount()
                + overview.correlation().observableFalseNegativeCount()
                + overview.correlation().trueNegativeCount();
        long failures = overview.operations().parserFailureCount()
                + overview.operations().technicalFallbackCount()
                + overview.operations().timeoutCount()
                + overview.operations().modelUnavailableCount();
        return new ReadinessSummary(
                overview.period(),
                overview.from(),
                overview.to(),
                overview.readinessRecommendation(),
                overview.hcad().qualification().minimumSampleSize(),
                overview.hcad().candidateCount(),
                overview.llm().totalDecisionCount(),
                overview.hcad().precision(),
                ratio(overview.correlation().observableFalseNegativeCount(), classified),
                overview.hcad().unknownRate(),
                ratio(failures, overview.llm().totalDecisionCount()),
                ratio(overview.operations().parserFailureCount(), overview.llm().totalDecisionCount()),
                ratio(overview.operations().technicalFallbackCount(), overview.llm().totalDecisionCount()),
                ratio(overview.operations().timeoutCount(), overview.llm().totalDecisionCount()),
                ratio(overview.operations().modelUnavailableCount(), overview.llm().totalDecisionCount()),
                overview.operations().averageLatencyMs(),
                p95Latency(overview.from(), overview.to()),
                overview.operations().estimatedWasteCostUsd(),
                overview.operations().estimatedSavedCostUsd());
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

    private LlmDecisionSummary llmSummary(LocalDateTime from, LocalDateTime to) {
        long total = count("ai_security_decision_observation", "created_at between ? and ?", from, to);
        long parserFailures = count("ai_security_decision_observation",
                "parser_failure = true and created_at between ? and ?", from, to);
        long technicalFallbacks = count("ai_security_decision_observation",
                "technical_fallback = true and created_at between ? and ?", from, to);
        long timeouts = count("ai_security_decision_observation",
                "timeout_failure = true and created_at between ? and ?", from, to);
        long modelUnavailable = count("ai_security_decision_observation",
                "model_unavailable = true and created_at between ? and ?", from, to);
        return new LlmDecisionSummary(
                total,
                count("ai_security_decision_observation",
                        "trigger_source in ('HCAD_PRE_TRIGGER', 'PENDING_REDLINE') and created_at between ? and ?",
                        from,
                        to),
                count("ai_security_decision_observation",
                        "trigger_relation in ('PROTECTABLE_ONLY', 'HCAD_AND_PROTECTABLE', 'PROTECTABLE_SUPPRESSED_BY_HCAD') and created_at between ? and ?",
                        from,
                        to),
                count("ai_security_decision_observation",
                        "trigger_relation = 'HCAD_AND_PROTECTABLE' and created_at between ? and ?",
                        from,
                        to),
                breakdown("ai_security_decision_observation", "trigger_source", from, to),
                breakdown("ai_security_decision_observation", "coalesce(final_action, 'UNKNOWN')", from, to),
                breakdown("ai_security_decision_observation", "coalesce(proposed_action, 'UNKNOWN')", from, to),
                breakdown("ai_security_decision_observation", "coalesce(final_action, 'UNKNOWN')", from, to),
                breakdown("ai_security_decision_observation", "coalesce(model_provider, 'UNKNOWN')", from, to),
                breakdown("ai_security_decision_observation", "coalesce(model_id, 'UNKNOWN')", from, to),
                breakdown("ai_security_decision_observation", "coalesce(prompt_template_key, 'UNKNOWN')", from, to),
                parserFailures,
                technicalFallbacks,
                timeouts,
                modelUnavailable,
                ratio(parserFailures, total),
                ratio(technicalFallbacks, total),
                ratio(timeouts, total),
                ratio(modelUnavailable, total),
                average("ai_security_decision_observation", "llm_latency_ms", from, to),
                p95Latency(from, to),
                numericBucketBreakdown("ai_security_decision_observation", "llm_risk_score", from, to),
                numericBucketBreakdown("ai_security_decision_observation", "llm_confidence", from, to));
    }

    private CorrelationSummary correlationSummary(LocalDateTime from, LocalDateTime to) {
        return new CorrelationSummary(
                countOutcome("TP", from, to),
                countOutcome("FP", from, to),
                countOutcome("FN", from, to),
                countOutcome("TN", from, to),
                countOutcome("UNKNOWN", from, to),
                countOutcome("UNOBSERVED", from, to),
                breakdown("hcad_llm_decision_correlation", "trigger_relation", from, to),
                breakdown("hcad_llm_decision_correlation", "outcome_class", from, to),
                correlationMatrix(from, to),
                recentCorrelations(from, to));
    }

    private OperationsSummary operationsSummary(LocalDateTime from, LocalDateTime to, HcadSummary hcad) {
        double cost = hcadProperties.getPreTrigger().getQualification().getEstimatedLlmCallCostUsd();
        long parserFailures = count("ai_security_decision_observation",
                "parser_failure = true and created_at between ? and ?", from, to);
        long technicalFallbacks = count("ai_security_decision_observation",
                "technical_fallback = true and created_at between ? and ?", from, to);
        long timeouts = count("ai_security_decision_observation",
                "timeout_failure = true and created_at between ? and ?", from, to);
        long modelUnavailable = count("ai_security_decision_observation",
                "model_unavailable = true and created_at between ? and ?", from, to);
        return new OperationsSummary(
                average("ai_security_decision_observation", "llm_latency_ms", from, to),
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
        String failureCauseExpression = """
                case
                  when failure_type is not null and failure_type <> '' and failure_type <> 'NONE' then failure_type
                  when parser_failure = true then 'PARSER_FAILURE'
                  when timeout_failure = true then 'TIMEOUT'
                  when model_unavailable = true then 'MODEL_UNAVAILABLE'
                  when technical_fallback = true then 'TECHNICAL_FALLBACK'
                  when fallback_category is not null and fallback_category <> '' and fallback_category <> 'NONE' then 'TECHNICAL_FALLBACK'
                  else null
                end
                """;
        String sql = """
                select metric_key, count(*) as failure_count
                  from (
                        select %s as metric_key
                          from ai_security_decision_observation
                         where created_at between ? and ?
                       ) failure_causes
                 where metric_key is not null
                 group by metric_key
                 order by failure_count desc, metric_key asc
                 limit ?
                """.formatted(failureCauseExpression);
        return jdbcOperations.query(
                sql,
                (rs, rowNum) -> new NamedCount(rs.getString("metric_key"), rs.getLong("failure_count")),
                from,
                to,
                BREAKDOWN_LIMIT);
    }

    private List<CorrelationMatrixRow> correlationMatrix(LocalDateTime from, LocalDateTime to) {
        MatrixCounts early = matrixCounts("""
                trigger_relation in ('HCAD_ONLY', 'HCAD_AND_PROTECTABLE')
                """, from, to);
        MatrixCounts missed = matrixCounts("""
                trigger_relation in ('PROTECTABLE_ONLY', 'OBSERVED_ONLY')
                """, from, to);
        MatrixCounts suppressed = matrixCounts("""
                trigger_relation in ('PROTECTABLE_SUPPRESSED_BY_HCAD', 'HCAD_SUPPRESSED_BY_PROTECTABLE')
                """, from, to);
        MatrixCounts unevaluated = matrixCounts("""
                trigger_relation = 'UNMATCHED_LLM'
                """, from, to);

        early = early.withNotCalled(count("hcad_detection_evaluation",
                "eligible = true and triggered_llm = false and decided_at is null and created_at between ? and ?",
                from, to));
        missed = missed.withNotCalled(count("hcad_detection_evaluation",
                "(eligible = false or eligible is null) and triggered_llm = false and duplicate_suppressed = false and decided_at is null and created_at between ? and ?",
                from, to));
        suppressed = suppressed.withNotCalled(count("hcad_detection_evaluation",
                "(duplicate_suppressed = true or coalesce(duplicate_suppressed_count, 0) > 0) and decided_at is null and created_at between ? and ?",
                from, to));

        return List.of(
                new CorrelationMatrixRow("HCAD_EARLY_TRIGGER", early.risk(), early.allow(), early.unknown(), early.notCalled()),
                new CorrelationMatrixRow("HCAD_MISSED_OBSERVED", missed.risk(), missed.allow(), missed.unknown(), missed.notCalled()),
                new CorrelationMatrixRow("HCAD_DUPLICATE_SUPPRESSED", suppressed.risk(), suppressed.allow(), suppressed.unknown(), suppressed.notCalled()),
                new CorrelationMatrixRow("HCAD_UNEVALUATED", unevaluated.risk(), unevaluated.allow(), unevaluated.unknown(), unevaluated.notCalled()));
    }

    private MatrixCounts matrixCounts(String relationClause, LocalDateTime from, LocalDateTime to) {
        return new MatrixCounts(
                count("hcad_llm_decision_correlation",
                        relationClause + " and outcome_class in ('TP', 'FN') and created_at between ? and ?",
                        from, to),
                count("hcad_llm_decision_correlation",
                        relationClause + " and outcome_class in ('FP', 'TN') and created_at between ? and ?",
                        from, to),
                count("hcad_llm_decision_correlation",
                        relationClause + " and outcome_class = 'UNKNOWN' and created_at between ? and ?",
                        from, to),
                count("hcad_llm_decision_correlation",
                        relationClause + " and outcome_class = 'UNOBSERVED' and created_at between ? and ?",
                        from, to));
    }

    private List<RecentCorrelation> recentCorrelations(LocalDateTime from, LocalDateTime to) {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return List.of();
        }
        return jdbcOperations.query("""
                        select correlation_id,
                               hcad_evaluation_id,
                               llm_observation_id,
                               event_id,
                               request_id,
                               user_id,
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
                          from hcad_llm_decision_correlation
                         where created_at between ? and ?
                         order by created_at desc
                         limit 50
                        """,
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
                        + correlation.falsePositiveCount()
                        + correlation.observableFalseNegativeCount()
                        + correlation.trueNegativeCount());
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

    private long countOutcome(String outcome, LocalDateTime from, LocalDateTime to) {
        return count("hcad_llm_decision_correlation",
                "outcome_class = ? and created_at between ? and ?",
                outcome,
                from,
                to);
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
                        """,
                Double.class,
                from,
                to);
        return value == null ? 0.0d : value;
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
        LocalDateTime to = LocalDateTime.now();
        return new TimeWindow(normalizedPeriod, from(normalizedPeriod, to), to);
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

    private record TimeWindow(String period, LocalDateTime from, LocalDateTime to) {
    }

    private record MatrixCounts(long risk, long allow, long unknown, long notCalled) {
        private MatrixCounts withNotCalled(long additionalNotCalled) {
            return new MatrixCounts(risk, allow, unknown, notCalled + additionalNotCalled);
        }
    }
}
