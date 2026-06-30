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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.properties.HcadProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.hcad.trigger.HcadPreTriggerMode;
import io.contexa.contexacore.hcad.semantic.HcadSemanticEvidenceCache;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.CorrelationMatrixRow;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.CorrelationSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.AffectedRequest;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.FailureSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.FeedbackLearningSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.LatencyBreakdownMetric;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.LlmDecisionSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.MetricValue;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.MonitoringResetRequest;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.MonitoringResetResponse;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.MonitoringSessionCurrent;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.MonitoringSessionSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.MonitorSnapshot;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.NamedCount;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.OperationsSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.OverviewSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.RecentFailure;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.RecentCorrelation;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.ReadinessBlocker;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.ReadinessSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.RuntimeModeSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.StandardMetrics;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.HcadSummary;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.transaction.annotation.Transactional;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class AiSecurityDecisionMonitoringService {

    private static final DateTimeFormatter ISO = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final int BREAKDOWN_LIMIT = 12;
    private static final int TELEMETRY_DELETE_BATCH_SIZE = 5000;
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
    private final Supplier<HcadSemanticEvidenceCache> semanticEvidenceCacheSupplier;

    public AiSecurityDecisionMonitoringService(
            HcadMonitoringService hcadMonitoringService,
            Supplier<JdbcOperations> jdbcOperationsSupplier,
            HcadProperties hcadProperties,
            SecurityZeroTrustProperties zeroTrustProperties,
            Supplier<HcadSemanticEvidenceCache> semanticEvidenceCacheSupplier) {
        this.hcadMonitoringService = hcadMonitoringService;
        this.jdbcOperationsSupplier = jdbcOperationsSupplier == null ? () -> null : jdbcOperationsSupplier;
        this.hcadProperties = hcadProperties;
        this.zeroTrustProperties = zeroTrustProperties;
        this.semanticEvidenceCacheSupplier = semanticEvidenceCacheSupplier == null ? () -> null : semanticEvidenceCacheSupplier;
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
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
                data.feedbackLearning(),
                data.readinessRecommendation());
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public LlmDecisionSummary llm(String period) {
        TimeWindow window = window(period);
        return withMetrics(llmSummary(window.from(), window.to()), monitorSnapshot(window), null);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public CorrelationSummary correlation(String period) {
        TimeWindow window = window(period);
        return withMetrics(correlationSummary(window.from(), window.to()), monitorSnapshot(window), null);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public FailureSummary failures(String period) {
        TimeWindow window = window(period);
        MonitorSnapshot snapshot = monitorSnapshot(window);
        OperationsSummary operations = operationsSummary(window.from(), window.to(), null);
        List<NamedCount> canonicalFailures = explicitFailureBreakdown(window.from(), window.to());
        return new FailureSummary(
                window.period(),
                ISO.format(window.from()),
                ISO.format(window.to()),
                snapshot.generatedAt(),
                snapshot,
                null,
                operations,
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

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
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
                operations.estimatedSavedCostUsd(),
                currentSession(data),
                sessionSummaries(8),
                readinessBlockers(data));
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
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


    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public MonitoringSessionCurrent currentSession(String period) {
        return currentSession(snapshotData(period));
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<MonitoringSessionSummary> sessionSummaries() {
        return sessionSummaries(10);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public MonitoringSessionSummary sessionSummary(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            return null;
        }
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return null;
        }
        try {
            return jdbcOperations.queryForObject(
                    """
                            select session_id, started_at, ended_at, period, reset_by, reset_reason,
                                   hcad_mode, llm_mode, llm_provider, llm_model,
                                   embedding_provider, embedding_model, prompt_template_version, policy_version,
                                   observed_request_count, hcad_candidate_count, hcad_triggered_llm_count,
                                   llm_decision_count, hcad_trigger_ai_decision_count, non_hcad_ai_decision_count,
                                   true_positive_count, false_positive_count, observable_false_negative_count,
                                   true_negative_count, unknown_count, hcad_precision, hcad_false_positive_rate,
                                   match_rate, mismatch_rate, observable_false_negative_rate, unknown_rate,
                                   failure_rate, timeout_rate, parser_failure_rate, model_unavailable_rate,
                                   average_latency_ms, p95_latency_ms, top_blockers_json, recommendation
                              from ai_security_monitoring_session_summary
                             where session_id = ?
                            """,
                    this::monitoringSessionSummary,
                    sessionId.trim());
        } catch (EmptyResultDataAccessException ex) {
            return null;
        }
    }

    private MonitoringSessionSummary monitoringSessionSummary(ResultSet rs, int rowNum) throws SQLException {
        return new MonitoringSessionSummary(
                rs.getString("session_id"),
                format(rs.getTimestamp("started_at").toLocalDateTime()),
                format(rs.getTimestamp("ended_at").toLocalDateTime()),
                rs.getString("period"),
                rs.getString("reset_by"),
                rs.getString("reset_reason"),
                rs.getString("hcad_mode"),
                rs.getString("llm_mode"),
                rs.getString("llm_provider"),
                rs.getString("llm_model"),
                rs.getString("embedding_provider"),
                rs.getString("embedding_model"),
                rs.getString("prompt_template_version"),
                rs.getString("policy_version"),
                rs.getLong("observed_request_count"),
                rs.getLong("hcad_candidate_count"),
                rs.getLong("hcad_triggered_llm_count"),
                rs.getLong("llm_decision_count"),
                rs.getLong("hcad_trigger_ai_decision_count"),
                rs.getLong("non_hcad_ai_decision_count"),
                rs.getLong("true_positive_count"),
                rs.getLong("false_positive_count"),
                rs.getLong("observable_false_negative_count"),
                rs.getLong("true_negative_count"),
                rs.getLong("unknown_count"),
                rs.getDouble("hcad_precision"),
                rs.getDouble("hcad_false_positive_rate"),
                rs.getDouble("match_rate"),
                rs.getDouble("mismatch_rate"),
                rs.getDouble("observable_false_negative_rate"),
                rs.getDouble("unknown_rate"),
                rs.getDouble("failure_rate"),
                rs.getDouble("timeout_rate"),
                rs.getDouble("parser_failure_rate"),
                rs.getDouble("model_unavailable_rate"),
                rs.getDouble("average_latency_ms"),
                rs.getDouble("p95_latency_ms"),
                rs.getString("top_blockers_json"),
                rs.getString("recommendation"));
    }
    @Transactional(transactionManager = "contexaTransactionManager")
    public MonitoringResetResponse resetMonitoring(MonitoringResetRequest request, String resetBy) {
        boolean resetLearningEvidence = request != null && Boolean.TRUE.equals(request.resetLearningEvidence());
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            throw new IllegalStateException("JdbcOperations is not available for AI monitor reset.");
        }
        LocalDateTime endedAt = LocalDateTime.now().withNano(0);
        LocalDateTime startedAt = currentSessionStart(endedAt);
        SnapshotData data = snapshotData(new TimeWindow("current", startedAt, endedAt, endedAt));
        String sessionId = UUID.randomUUID().toString();
        String normalizedResetBy = resetBy == null || resetBy.isBlank() ? "unknown" : resetBy.trim();
        String reason = request == null || request.reason() == null || request.reason().isBlank()
                ? "Monitoring restarted by administrator."
                : request.reason().trim();
        MonitoringSessionSummary archived = sessionSummary(sessionId, data, normalizedResetBy, reason);
        insertSessionSummary(jdbcOperations, archived, summaryJson(data));
        boolean learningEvidenceReset = clearLearningEvidenceCache(resetLearningEvidence);
        long deletedCorrelation = deleteTelemetryInBatches(
                jdbcOperations,
                "hcad_llm_decision_correlation",
                "correlation_id");
        long deletedAi = deleteTelemetryInBatches(
                jdbcOperations,
                "ai_security_decision_observation",
                "observation_id");
        long deletedHcad = deleteTelemetryInBatches(
                jdbcOperations,
                "hcad_detection_evaluation",
                "evaluation_id");
        writeResetAudit(jdbcOperations, normalizedResetBy, reason, sessionId, deletedHcad, deletedAi, deletedCorrelation);
        MonitoringSessionCurrent newSession = new MonitoringSessionCurrent(
                "current",
                format(endedAt),
                format(endedAt),
                format(endedAt),
                0L,
                0L,
                0L,
                0L,
                0L,
                0L,
                "INSUFFICIENT_DATA");
        return new MonitoringResetResponse(
                sessionId,
                format(startedAt),
                format(endedAt),
                deletedHcad,
                deletedAi,
                deletedCorrelation,
                learningEvidenceReset,
                archived,
                newSession);
    }
    private long deleteTelemetryInBatches(JdbcOperations jdbcOperations, String tableName, String idColumn) {
        long total = 0L;
        int deleted;
        String sql = "delete from " + tableName
                + " where " + idColumn + " in (select " + idColumn + " from " + tableName
                + " order by created_at, " + idColumn + " limit ?)";
        do {
            deleted = jdbcOperations.update(sql, TELEMETRY_DELETE_BATCH_SIZE);
            total += deleted;
        } while (deleted == TELEMETRY_DELETE_BATCH_SIZE);
        return total;
    }
    private boolean clearLearningEvidenceCache(boolean requested) {
        if (!requested) {
            return false;
        }
        if (semanticEvidenceCacheSupplier == null) {
            return false;
        }
        HcadSemanticEvidenceCache cache = semanticEvidenceCacheSupplier.get();
        if (cache == null) {
            return false;
        }
        cache.clear();
        return true;
    }
    private SnapshotData snapshotData(String period) {
        return snapshotData(window(period));
    }

    private SnapshotData snapshotData(TimeWindow window) {
        MonitorSnapshot snapshot = monitorSnapshot(window);
        HcadSummary hcad = hcadMonitoringService.summarize(window.period(), window.from(), window.to());
        LlmDecisionSummary llm = llmSummary(window.from(), window.to());
        CorrelationSummary correlation = correlationSummary(window.from(), window.to());
        OperationsSummary operations = operationsSummary(window.from(), window.to(), hcad);
        FeedbackLearningSummary feedbackLearning = feedbackLearningSummary(window.from(), window.to());
        StandardMetrics metrics = standardMetrics(hcad, llm, correlation, operations);
        return new SnapshotData(
                window,
                snapshot,
                hcad,
                llm,
                correlation,
                operations,
                feedbackLearning,
                metrics,
                readinessRecommendation(hcad, llm, correlation, operations));
    }

    private MonitorSnapshot monitorSnapshot(TimeWindow window) {
        return new MonitorSnapshot(
                window.period(),
                ISO.format(window.from()),
                ISO.format(window.to()),
                ISO.format(window.generatedAt()),
                runtimeModeSummary());
    }


    private MonitoringSessionCurrent currentSession(SnapshotData data) {
        long hcadAiDecisions = data.llm().hcadPreTriggerDecisionCount();
        long nonHcadAiDecisions = Math.max(0L, data.llm().totalDecisionCount() - hcadAiDecisions);
        return new MonitoringSessionCurrent(
                "current",
                format(currentSessionStart(data.window().generatedAt())),
                format(data.window().from()),
                format(data.window().to()),
                data.hcad().observedRequestCount(),
                data.hcad().candidateCount(),
                data.hcad().triggeredLlmCount(),
                data.llm().totalDecisionCount(),
                hcadAiDecisions,
                nonHcadAiDecisions,
                data.readinessRecommendation());
    }

    private List<MonitoringSessionSummary> sessionSummaries(int limit) {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return List.of();
        }
        return jdbcOperations.query(
                """
                        select session_id, started_at, ended_at, period, reset_by, reset_reason,
                               hcad_mode, llm_mode, llm_provider, llm_model,
                               embedding_provider, embedding_model, prompt_template_version, policy_version,
                               observed_request_count, hcad_candidate_count, hcad_triggered_llm_count,
                               llm_decision_count, hcad_trigger_ai_decision_count, non_hcad_ai_decision_count,
                               true_positive_count, false_positive_count, observable_false_negative_count,
                               true_negative_count, unknown_count, hcad_precision, hcad_false_positive_rate,
                               match_rate, mismatch_rate, observable_false_negative_rate, unknown_rate,
                               failure_rate, timeout_rate, parser_failure_rate, model_unavailable_rate,
                               average_latency_ms, p95_latency_ms, top_blockers_json, recommendation
                          from ai_security_monitoring_session_summary
                         order by ended_at desc
                         limit ?
                        """,
                this::monitoringSessionSummary,
                Math.max(1, limit));
    }

    private MonitoringSessionSummary sessionSummary(
            String sessionId,
            SnapshotData data,
            String resetBy,
            String reason) {
        long hcadAiDecisions = data.llm().hcadPreTriggerDecisionCount();
        long nonHcadAiDecisions = Math.max(0L, data.llm().totalDecisionCount() - hcadAiDecisions);
        RuntimeModeSummary runtimeModes = data.snapshot().runtimeModes();
        return new MonitoringSessionSummary(
                sessionId,
                format(data.window().from()),
                format(data.window().to()),
                data.window().period(),
                resetBy,
                reason,
                runtimeModes == null ? "UNKNOWN" : runtimeModes.hcadMode(),
                runtimeModes == null ? "UNKNOWN" : runtimeModes.llmMode(),
                firstBreakdownKey(data.llm().providerBreakdown()),
                firstBreakdownKey(data.llm().modelBreakdown()),
                "UNKNOWN",
                "UNKNOWN",
                firstBreakdownKey(data.llm().promptTemplateBreakdown()),
                currentPolicyVersion(),
                data.hcad().observedRequestCount(),
                data.hcad().candidateCount(),
                data.hcad().triggeredLlmCount(),
                data.llm().totalDecisionCount(),
                hcadAiDecisions,
                nonHcadAiDecisions,
                data.correlation().truePositiveCount(),
                data.correlation().falsePositiveCount(),
                data.correlation().observableFalseNegativeCount(),
                data.correlation().trueNegativeCount(),
                data.correlation().unknownCount(),
                metricNumber(data.metrics().hcadPrecision()),
                metricNumber(data.metrics().falsePositiveRate()),
                metricNumber(data.metrics().matchRate()),
                metricNumber(data.metrics().mismatchRate()),
                metricNumber(data.metrics().observableFalseNegativeRate()),
                metricNumber(data.metrics().unknownRate()),
                metricNumber(data.metrics().failureRate()),
                metricNumber(data.metrics().timeoutRate()),
                data.llm().parserFailureRate(),
                data.llm().modelUnavailableRate(),
                data.operations().averageLatencyMs(),
                data.llm().p95LatencyMs(),
                topBlockersJson(data),
                data.readinessRecommendation());
    }
    private void insertSessionSummary(
            JdbcOperations jdbcOperations,
            MonitoringSessionSummary summary,
            String summaryJson) {
        jdbcOperations.update(
                """
                        insert into ai_security_monitoring_session_summary (
                            session_id, started_at, ended_at, period, reset_by, reset_reason,
                            hcad_mode, llm_mode, llm_provider, llm_model, embedding_provider, embedding_model,
                            prompt_template_version, policy_version,
                            observed_request_count, hcad_candidate_count, hcad_triggered_llm_count,
                            llm_decision_count, hcad_trigger_ai_decision_count, non_hcad_ai_decision_count,
                            true_positive_count, false_positive_count, observable_false_negative_count,
                            true_negative_count, unknown_count, hcad_precision, hcad_false_positive_rate,
                            match_rate, mismatch_rate, observable_false_negative_rate, unknown_rate, failure_rate,
                            timeout_rate, parser_failure_rate, model_unavailable_rate,
                            average_latency_ms, p95_latency_ms, recommendation, top_blockers_json, summary_json
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                summary.sessionId(),
                LocalDateTime.parse(summary.startedAt(), ISO),
                LocalDateTime.parse(summary.endedAt(), ISO),
                summary.period(),
                summary.resetBy(),
                summary.resetReason(),
                summary.hcadMode(),
                summary.llmMode(),
                summary.llmProvider(),
                summary.llmModel(),
                summary.embeddingProvider(),
                summary.embeddingModel(),
                summary.promptTemplateVersion(),
                summary.policyVersion(),
                summary.observedRequestCount(),
                summary.hcadCandidateCount(),
                summary.hcadTriggeredLlmCount(),
                summary.llmDecisionCount(),
                summary.hcadTriggerAiDecisionCount(),
                summary.nonHcadAiDecisionCount(),
                summary.truePositiveCount(),
                summary.falsePositiveCount(),
                summary.observableFalseNegativeCount(),
                summary.trueNegativeCount(),
                summary.unknownCount(),
                summary.hcadPrecision(),
                summary.hcadFalsePositiveRate(),
                summary.matchRate(),
                summary.mismatchRate(),
                summary.observableFalseNegativeRate(),
                summary.unknownRate(),
                summary.failureRate(),
                summary.timeoutRate(),
                summary.parserFailureRate(),
                summary.modelUnavailableRate(),
                summary.averageLatencyMs(),
                summary.p95LatencyMs(),
                summary.recommendation(),
                summary.topBlockersJson(),
                summaryJson);
    }
    private String topBlockersJson(SnapshotData data) {
        try {
            return OBJECT_MAPPER.writeValueAsString(readinessBlockers(data));
        } catch (JsonProcessingException ex) {
            return "[]";
        }
    }

    private String firstBreakdownKey(List<NamedCount> items) {
        if (items == null || items.isEmpty()) {
            return "UNKNOWN";
        }
        return items.stream()
                .filter(item -> item != null && item.count() > 0)
                .map(NamedCount::key)
                .filter(key -> key != null && !key.isBlank())
                .findFirst()
                .orElse("UNKNOWN");
    }

    private String currentPolicyVersion() {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return "UNKNOWN";
        }
        try {
            Long version = jdbcOperations.queryForObject("select max(id) from policy_version", Long.class);
            return version == null ? "NONE" : Long.toString(version);
        } catch (RuntimeException ex) {
            return "UNKNOWN";
        }
    }
    private String summaryJson(SnapshotData data) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("period", data.window().period());
        payload.put("from", format(data.window().from()));
        payload.put("to", format(data.window().to()));
        payload.put("recommendation", data.readinessRecommendation());
        payload.put("runtimeModes", data.snapshot().runtimeModes());
        payload.put("llmProvider", firstBreakdownKey(data.llm().providerBreakdown()));
        payload.put("llmModel", firstBreakdownKey(data.llm().modelBreakdown()));
        payload.put("promptTemplateVersion", firstBreakdownKey(data.llm().promptTemplateBreakdown()));
        payload.put("policyVersion", currentPolicyVersion());
        payload.put("topBlockers", readinessBlockers(data));
        payload.put("observedRequestCount", data.hcad().observedRequestCount());
        payload.put("hcadCandidateCount", data.hcad().candidateCount());
        payload.put("hcadTriggeredLlmCount", data.hcad().triggeredLlmCount());
        payload.put("llmDecisionCount", data.llm().totalDecisionCount());
        payload.put("truePositiveCount", data.correlation().truePositiveCount());
        payload.put("falsePositiveCount", data.correlation().falsePositiveCount());
        payload.put("observableFalseNegativeCount", data.correlation().observableFalseNegativeCount());
        payload.put("trueNegativeCount", data.correlation().trueNegativeCount());
        payload.put("unknownCount", data.correlation().unknownCount());
        payload.put("hcadPrecision", metricNumber(data.metrics().hcadPrecision()));
        payload.put("hcadFalsePositiveRate", metricNumber(data.metrics().falsePositiveRate()));
        payload.put("matchRate", metricNumber(data.metrics().matchRate()));
        payload.put("mismatchRate", metricNumber(data.metrics().mismatchRate()));
        payload.put("observableFalseNegativeRate", metricNumber(data.metrics().observableFalseNegativeRate()));
        payload.put("unknownRate", metricNumber(data.metrics().unknownRate()));
        payload.put("failureRate", metricNumber(data.metrics().failureRate()));
        payload.put("timeoutRate", metricNumber(data.metrics().timeoutRate()));
        payload.put("parserFailureRate", data.llm().parserFailureRate());
        payload.put("modelUnavailableRate", data.llm().modelUnavailableRate());
        payload.put("averageLatencyMs", data.operations().averageLatencyMs());
        payload.put("p95LatencyMs", data.llm().p95LatencyMs());
        try {
            return OBJECT_MAPPER.writeValueAsString(payload);
        } catch (JsonProcessingException ex) {
            return "{}";
        }
    }

    private List<ReadinessBlocker> readinessBlockers(SnapshotData data) {
        List<ReadinessBlocker> blockers = new ArrayList<>();
        long minimumSample = data.hcad().qualification().minimumSampleSize();
        long candidateCount = data.hcad().candidateCount();
        if (candidateCount < minimumSample) {
            blockers.add(new ReadinessBlocker(
                    "SAMPLE",
                    "Sample size is not enough",
                    numberText(candidateCount),
                    numberText(minimumSample) + " or more",
                    "Collect enough real request data, then review the recommendation again."));
        }
        long llmDecisionCount = data.llm().totalDecisionCount();
        if (llmDecisionCount <= 0) {
            blockers.add(new ReadinessBlocker(
                    "NO_LLM_DECISION",
                    "No AI decision data",
                    "0",
                    "1 or more",
                    "Verify that protectable resources or HCAD candidates reach AI decision logging."));
            return blockers;
        }
        double precision = metricNumber(data.metrics().hcadPrecision());
        double falseNegativeRate = metricNumber(data.metrics().observableFalseNegativeRate());
        double unknownRate = metricNumber(data.metrics().unknownRate());
        double failureRate = metricNumber(data.metrics().failureRate());
        if (precision < 0.80d) {
            blockers.add(new ReadinessBlocker(
                    "HCAD_PRECISION",
                    "HCAD precision is below target",
                    percentText(precision),
                    "80% or more",
                    "Review false positives against baseline, semantic evidence, and HCAD signals."));
        }
        if (falseNegativeRate > 0.10d) {
            blockers.add(new ReadinessBlocker(
                    "OBSERVABLE_FN",
                    "AI risk was found after HCAD missed it",
                    percentText(falseNegativeRate),
                    "10% or less",
                    "Analyze protectable AI risk decisions that had no stored HCAD risk candidate."));
        }
        if (unknownRate > 0.40d) {
            blockers.add(new ReadinessBlocker(
                    "UNKNOWN",
                    "Unknown comparison rate is high",
                    percentText(unknownRate),
                    "40% or less",
                    "Reduce unknown outcomes so more decisions can be compared."));
        }
        if (failureRate > 0.10d) {
            blockers.add(new ReadinessBlocker(
                    "FAILURE",
                    "AI analysis failure rate is high",
                    percentText(failureRate),
                    "10% or less",
                    "Fix timeout, parser failure, and model unavailable causes first."));
        }
        addFailureBlocker(blockers, "TIMEOUT", data.llm().timeoutCount(), data.llm().timeoutRate(),
                "AI analysis timed out",
                "Inspect OpenAI latency, network, prompt size, and timeout settings before switching modes.");
        addFailureBlocker(blockers, "PARSER_FAILURE", data.llm().parserFailureCount(), data.llm().parserFailureRate(),
                "AI response parsing failed",
                "Check the decision prompt contract, response schema, and parser logs.");
        addFailureBlocker(blockers, "MODEL_UNAVAILABLE", data.llm().modelUnavailableCount(), data.llm().modelUnavailableRate(),
                "AI model was unavailable",
                "Check provider/model configuration and runtime LLM client availability.");
        addFailureBlocker(blockers, "TECHNICAL_FALLBACK", data.llm().technicalFallbackCount(), data.llm().technicalFallbackRate(),
                "Technical fallback was used",
                "Remove fallback causes before trusting transition recommendations.");
        return blockers;
    }

    private void addFailureBlocker(
            List<ReadinessBlocker> blockers,
            String key,
            long count,
            double rate,
            String title,
            String action) {
        if (count <= 0L && rate <= 0.0d) {
            return;
        }
        blockers.add(new ReadinessBlocker(
                key,
                title,
                count + " / " + percentText(rate),
                "0",
                action));
    }

    private LocalDateTime currentSessionStart(LocalDateTime fallbackNow) {
        LocalDateTime lastArchivedEnd = queryDateTime(
                "select max(ended_at) from ai_security_monitoring_session_summary");
        if (lastArchivedEnd != null) {
            return lastArchivedEnd.withNano(0);
        }
        LocalDateTime earliestTelemetry = queryDateTime(
                """
                        select min(created_at)
                          from (
                                select min(created_at) as created_at from hcad_detection_evaluation
                                union all
                                select min(created_at) as created_at from ai_security_decision_observation
                                union all
                                select min(created_at) as created_at from hcad_llm_decision_correlation
                               ) s
                        """);
        return earliestTelemetry == null ? fallbackNow : earliestTelemetry.withNano(0);
    }

    private LocalDateTime queryDateTime(String sql, Object... args) {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return null;
        }
        try {
            return jdbcOperations.queryForObject(sql, LocalDateTime.class, args);
        } catch (EmptyResultDataAccessException ex) {
            return null;
        }
    }

    private void writeResetAudit(
            JdbcOperations jdbcOperations,
            String resetBy,
            String reason,
            String sessionId,
            long deletedHcad,
            long deletedAi,
            long deletedCorrelation) {
        String details = "sessionId=" + sessionId
                + ", deletedHcad=" + deletedHcad
                + ", deletedAi=" + deletedAi
                + ", deletedCorrelation=" + deletedCorrelation;
        jdbcOperations.update(
                """
                        insert into audit_log (
                            principal_name, resource_identifier, action, decision, reason, details,
                            outcome, event_category, event_source, request_uri
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                resetBy,
                "AI_SECURITY_MONITORING",
                "RESET_MONITORING_DATA",
                "ALLOW",
                reason,
                details,
                "SUCCESS",
                "AI_MONITOR",
                "AiSecurityDecisionMonitoringService",
                "/contexa/admin/api/ai-monitor/reset");
    }

    private String percentText(double value) {
        return String.format(Locale.ROOT, "%.1f%%", value * 100.0d);
    }

    private String numberText(long value) {
        return Long.toString(value);
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
                countMetric("observedRequests", "Observed requests", "Monitorable requests in the selected period.",
                        hcad.observedRequestCount()),
                countMetric("hcadEvaluations", "HCAD evaluations", "Requests or windows evaluated by HCAD.",
                        hcad.candidateCount()),
                countMetric("hcadAiConnected", "HCAD to AI", "HCAD candidates connected to AI analysis.",
                        hcad.triggeredLlmCount()),
                countMetric("totalAiDecisions", "AI decisions", "Requests analyzed by AI.",
                        llm.totalDecisionCount()),
                countMetric("clearOutcomes", "Clear outcomes", "Comparable TP/FP/FN/TN outcomes.",
                        classified),
                ratioMetric("hcadPrecision", "HCAD precision", "Share of HCAD risk candidates also judged risky by AI.",
                        tp, tp + fp, "NO_HCAD_RISK_COMPARISON"),
                ratioMetric("matchRate", "Match rate", "Share of HCAD and AI decisions moving in the same direction.",
                        tp + tn, classified, "NO_CLASSIFIED_COMPARISON"),
                ratioMetric("mismatchRate", "Mismatch rate", "Share of HCAD and AI decisions that conflict.",
                        fp + fn, classified, "NO_CLASSIFIED_COMPARISON"),
                ratioMetric("falsePositiveRate", "False positive rate", "HCAD risk candidates that AI allowed.",
                        fp, tp + fp, "NO_HCAD_RISK_COMPARISON"),
                ratioMetric("observableFalseNegativeRate", "AI risk found after HCAD missed it", "Protectable AI risk decisions without a stored HCAD risk candidate.",
                        fn, tp + fn, "NO_AI_RISK_COMPARISON"),
                ratioMetric("unknownRate", "Unknown rate", "Share of outcomes that cannot be compared reliably.",
                        unknown, comparisonTotal, "NO_COMPARISON_DATA"),
                ratioMetric("failureRate", "AI analysis failure rate", "Share of AI analyses that failed to complete normally.",
                        failures, llm.totalDecisionCount(), "NO_AI_DECISION_DATA"),
                ratioMetric("timeoutRate", "Timeout rate", "Share of AI analyses that timed out.",
                        operations.timeoutCount(), llm.totalDecisionCount(), "NO_AI_DECISION_DATA"),
                durationMetric("averageLatencyMs", "Average analysis latency", "Average AI analysis response time.",
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
                hcad == null ? 0L : hcad.falsePositiveCount(),
                hcad == null ? 0.0d : hcad.falsePositiveCount() * cost,
                hcad == null ? 0.0d : hcad.duplicateSuppressedCount() * cost,
                latencyBreakdown(from, to));
    }


    private FeedbackLearningSummary feedbackLearningSummary(LocalDateTime from, LocalDateTime to) {
        long normalEvidence = countSemanticEvidence(from, to, "%normal_request_similarity%");
        long riskEvidence = countSemanticEvidence(from, to, "%risk_request_similarity%")
                + countSemanticEvidence(from, to, "%resource_llm_decision_summary%");
        long learningExcluded = countAi("""
                created_at between ? and ?
                and (
                    success = false
                    or coalesce(failure_type, '') <> ''
                    or upper(coalesce(nullif(final_action, ''), nullif(proposed_action, ''), 'UNKNOWN')) not in ('ALLOW', 'CHALLENGE', 'BLOCK')
                )
                """, from, to);
        long cacheHits = countHcad("""
                created_at between ? and ?
                and lower(coalesce(semantic_evidence_explanation_json, '')) like ?
                and lower(coalesce(semantic_evidence_explanation_json, '')) like ?
                """, from, to, "%semanticevidencefreshhit%", "%true%");
        long cacheMisses = countHcad("""
                created_at between ? and ?
                and (
                    lower(coalesce(semantic_evidence_explanation_json, '')) like ?
                    or lower(coalesce(semantic_evidence_explanation_json, '')) like ?
                )
                """, from, to, "%cache_miss%", "%source_absent%");
        long cacheStale = countHcad("""
                created_at between ? and ?
                and lower(coalesce(semantic_evidence_explanation_json, '')) like ?
                """, from, to, "%stale_hit%");
        long normalSuppressed = countHcad("""
                created_at between ? and ?
                and lower(coalesce(semantic_evidence_explanation_json, '')) like ?
                and triggered_llm = false
                """, from, to, "%normal_request_similarity%");
        long riskHitLlmConnections = countHcad("""
                created_at between ? and ?
                and (
                    lower(coalesce(semantic_evidence_explanation_json, '')) like ?
                    or lower(coalesce(semantic_evidence_explanation_json, '')) like ?
                )
                and triggered_llm = true
                """, from, to, "%risk_request_similarity%", "%resource_llm_decision_summary%");
        long riskHitEligible = countHcad("""
                created_at between ? and ?
                and (
                    lower(coalesce(semantic_evidence_explanation_json, '')) like ?
                    or lower(coalesce(semantic_evidence_explanation_json, '')) like ?
                )
                and eligible = true
                """, from, to, "%risk_request_similarity%", "%resource_llm_decision_summary%");
        return new FeedbackLearningSummary(
                normalEvidence,
                riskEvidence,
                learningExcluded,
                cacheHits,
                cacheMisses,
                cacheStale,
                riskHitLlmConnections,
                riskHitEligible,
                ratio(normalSuppressed, normalEvidence),
                ratio(riskHitLlmConnections, riskEvidence),
                ratio(riskHitEligible, riskEvidence));
    }

    private long countSemanticEvidence(LocalDateTime from, LocalDateTime to, String pattern) {
        return countHcad("""
                created_at between ? and ?
                and lower(coalesce(semantic_evidence_explanation_json, '')) like ?
                """, from, to, pattern);
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
            return "INSUFFICIENT_DATA";
        }
        long comparable = correlation.truePositiveCount()
                + correlation.falsePositiveCount()
                + correlation.observableFalseNegativeCount()
                + correlation.trueNegativeCount();
        double precision = ratio(correlation.truePositiveCount(),
                correlation.truePositiveCount() + correlation.falsePositiveCount());
        double matchRate = ratio(correlation.truePositiveCount() + correlation.trueNegativeCount(), comparable);
        double failureRate = ratio(
                operations.parserFailureCount()
                        + operations.technicalFallbackCount()
                        + operations.timeoutCount()
                        + operations.modelUnavailableCount(),
                llm.totalDecisionCount());
        double observableFnRate = ratio(correlation.observableFalseNegativeCount(),
                correlation.truePositiveCount()
                        + correlation.observableFalseNegativeCount());
        double unknownRate = ratio(correlation.unknownCount(), comparable + correlation.unknownCount());
        if (failureRate >= 0.10d || observableFnRate >= 0.10d || unknownRate >= 0.40d || precision < 0.80d) {
            return "DO_NOT_RECOMMEND";
        }
        if (precision >= 0.95d && matchRate >= 0.95d) {
            return "READY_FOR_ENFORCE_REVIEW";
        }
        if (precision >= 0.90d && matchRate >= 0.90d) {
            return "READY_FOR_LIMITED_REVIEW";
        }
        return "KEEP_MONITORING";
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

    private List<LatencyBreakdownMetric> latencyBreakdown(LocalDateTime from, LocalDateTime to) {
        return List.of(
                latencyMetric("QUEUE_WAIT_MS", "queueWaitMs", from, to),
                latencyMetric("PROMPT_BUILD_MS", "promptBuildMs", from, to),
                latencyMetric("RAG_VECTOR_MS", "ragVectorMs", from, to),
                latencyMetric("OPENAI_CALL_MS", "openAiCallMs", from, to),
                latencyMetric("PARSE_MS", "parseMs", from, to),
                latencyMetric("PERSIST_MS", "persistMs", from, to),
                latencyMetric("TOTAL_ANALYSIS_MS", "totalAnalysisMs", from, to));
    }

    private LatencyBreakdownMetric latencyMetric(String key, String jsonKey, LocalDateTime from, LocalDateTime to) {
        return new LatencyBreakdownMetric(
                key,
                averageLatencyMetadata(jsonKey, from, to),
                p95LatencyMetadata(jsonKey, from, to));
    }

    private double averageLatencyMetadata(String jsonKey, LocalDateTime from, LocalDateTime to) {
        String columnName = latencyColumn(jsonKey);
        if (columnName == null) {
            return 0.0d;
        }
        return averageAi(columnName, from, to);
    }

    private double p95LatencyMetadata(String jsonKey, LocalDateTime from, LocalDateTime to) {
        String columnName = latencyColumn(jsonKey);
        if (columnName == null) {
            return 0.0d;
        }
        return p95LatencyColumn(columnName, from, to);
    }

    private double p95LatencyColumn(String columnName, LocalDateTime from, LocalDateTime to) {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return 0.0d;
        }
        Double value = jdbcOperations.queryForObject(
                "select percentile_cont(0.95) within group (order by " + columnName + ") "
                        + "from ai_security_decision_observation"
                        + " where created_at between ? and ? and " + columnName + " is not null"
                        + " and " + monitorablePath("request_path"),
                Double.class,
                from,
                to);
        return value == null ? 0.0d : value;
    }

    private String latencyColumn(String jsonKey) {
        return switch (jsonKey) {
            case "queueWaitMs" -> "queue_wait_ms";
            case "promptBuildMs" -> "prompt_build_ms";
            case "ragVectorMs" -> "rag_vector_ms";
            case "openAiCallMs" -> "openai_call_ms";
            case "parseMs" -> "parse_ms";
            case "persistMs" -> "persist_ms";
            case "totalAnalysisMs" -> "total_analysis_ms";
            default -> null;
        };
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
        LocalDateTime periodFrom = from(normalizedPeriod, generatedAt);
        LocalDateTime sessionStart = currentSessionStart(generatedAt);
        LocalDateTime effectiveFrom = sessionStart.isAfter(periodFrom) ? sessionStart : periodFrom;
        return new TimeWindow(normalizedPeriod, effectiveFrom, generatedAt, generatedAt);
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
            FeedbackLearningSummary feedbackLearning,
            StandardMetrics metrics,
            String readinessRecommendation) {
    }

    private record MatrixCounts(long risk, long allow, long unknown, long notCalled) {
        private MatrixCounts withNotCalled(long additionalNotCalled) {
            return new MatrixCounts(risk, allow, unknown, notCalled + additionalNotCalled);
        }
    }
}











