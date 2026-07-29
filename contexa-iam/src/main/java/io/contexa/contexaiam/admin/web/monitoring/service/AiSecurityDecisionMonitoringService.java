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
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.AffectedRequest;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.FailureSummary;
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
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.ReadinessBlocker;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.ReadinessSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.RuntimeModeSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.StandardMetrics;
import org.springframework.context.MessageSource;
import org.springframework.context.support.StaticMessageSource;
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
    public static final String RESET_CONFIRMATION_TEXT = "RESET";
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
                or lower(coalesce(@PATH@, '')) like '/contexa/css/%'
                or lower(coalesce(@PATH@, '')) like '/fonts/%'
                or lower(coalesce(@PATH@, '')) like '/contexa/img/%'
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

    private final Supplier<JdbcOperations> jdbcOperationsSupplier;
    private final SecurityZeroTrustProperties zeroTrustProperties;
    private final MessageSource messageSource;

    public AiSecurityDecisionMonitoringService(
            Supplier<JdbcOperations> jdbcOperationsSupplier,
            SecurityZeroTrustProperties zeroTrustProperties) {
        this(
                jdbcOperationsSupplier,
                zeroTrustProperties,
                new StaticMessageSource());
    }

    public AiSecurityDecisionMonitoringService(
            Supplier<JdbcOperations> jdbcOperationsSupplier,
            SecurityZeroTrustProperties zeroTrustProperties,
            MessageSource messageSource) {
        this.jdbcOperationsSupplier = jdbcOperationsSupplier == null ? () -> null : jdbcOperationsSupplier;
        this.zeroTrustProperties = zeroTrustProperties;
        this.messageSource = messageSource == null ? new StaticMessageSource() : messageSource;
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
                withMetrics(data.llm(), data.snapshot(), data.metrics()),
                data.operations(),
                data.readinessRecommendation());
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public LlmDecisionSummary llm(String period) {
        TimeWindow window = window(period);
        return withMetrics(llmSummary(window.from(), window.to()), monitorSnapshot(window), null);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public FailureSummary failures(String period) {
        TimeWindow window = window(period);
        MonitorSnapshot snapshot = monitorSnapshot(window);
        OperationsSummary operations = operationsSummary(window.from(), window.to());
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
                llm.totalDecisionCount(),
                metricNumber(data.metrics().failureRate()),
                llm.parserFailureRate(),
                llm.technicalFallbackRate(),
                llm.timeoutRate(),
                llm.modelUnavailableRate(),
                operations.averageLatencyMs(),
                p95Latency(data.window().from(), data.window().to()),
                currentSession(data),
                sessionSummaries(8),
                readinessBlockers(data));
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public String exportCsv(String period, String type, Locale locale) {
        String normalizedType = type == null || type.isBlank()
                ? "overview"
                : type.trim().toLowerCase(Locale.ROOT);
        return switch (normalizedType) {
            case "llm" -> {
                LlmDecisionSummary summary = llm(period);
                yield csv(List.of(
                        row(message(locale, "monitoring.csv.metric"), message(locale, "monitoring.csv.value")),
                        row(message(locale, "monitoring.csv.totalLlmDecisions"),
                                summary.totalDecisionCount()),
                        row(message(locale, "monitoring.csv.protectableDecisions"),
                                summary.protectableDecisionCount())));
            }
            case "failures" -> {
                FailureSummary summary = failures(period);
                yield csv(List.of(
                        row(message(locale, "monitoring.csv.metric"), message(locale, "monitoring.csv.value")),
                        row(message(locale, "monitoring.csv.parserFailures"),
                                summary.operations().parserFailureCount()),
                        row(message(locale, "monitoring.csv.technicalFallbacks"),
                                summary.operations().technicalFallbackCount()),
                        row(message(locale, "monitoring.csv.timeouts"),
                                summary.operations().timeoutCount()),
                        row(message(locale, "monitoring.csv.modelUnavailable"),
                                summary.operations().modelUnavailableCount())));
            }
            case "readiness" -> {
                ReadinessSummary summary = readiness(period);
                yield csv(List.of(
                        row(message(locale, "monitoring.csv.metric"), message(locale, "monitoring.csv.value")),
                        row(message(locale, "monitoring.csv.readinessRecommendation"), summary.recommendation()),
                        row(message(locale, "monitoring.csv.failureRate"),
                                summary.failureRate())));
            }
            default -> {
                OverviewSummary summary = overview(period);
                yield csv(List.of(
                        row(message(locale, "monitoring.csv.metric"), message(locale, "monitoring.csv.value")),
                        row(message(locale, "monitoring.csv.llmDecisions"),
                                summary.llm().totalDecisionCount()),
                        row(message(locale, "monitoring.csv.timeouts"),
                                summary.operations().timeoutCount()),
                        row(message(locale, "monitoring.csv.readinessRecommendation"), summary.readinessRecommendation())));
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
                                   llm_mode, llm_provider, llm_model, prompt_template_version, policy_version,
                                   llm_decision_count,
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
                rs.getString("llm_mode"),
                rs.getString("llm_provider"),
                rs.getString("llm_model"),
                rs.getString("prompt_template_version"),
                rs.getString("policy_version"),
                rs.getLong("llm_decision_count"),
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
        validateResetConfirmation(request);
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
        long deletedAi = deleteTelemetryInBatches(
                jdbcOperations,
                "ai_security_decision_observation",
                "observation_id");
        writeResetAudit(jdbcOperations, normalizedResetBy, reason, sessionId, deletedAi);
        MonitoringSessionCurrent newSession = new MonitoringSessionCurrent(
                "current",
                format(endedAt),
                format(endedAt),
                format(endedAt),
                0L,
                "INSUFFICIENT_DATA");
        return new MonitoringResetResponse(
                sessionId,
                format(startedAt),
                format(endedAt),
                deletedAi,
                archived,
                newSession);
    }
    public static boolean isResetConfirmationAccepted(MonitoringResetRequest request) {
        if (request == null || request.confirmationText() == null) {
            return false;
        }
        return RESET_CONFIRMATION_TEXT.equals(request.confirmationText().trim());
    }

    private static void validateResetConfirmation(MonitoringResetRequest request) {
        if (!isResetConfirmationAccepted(request)) {
            throw new IllegalArgumentException("AI security monitoring reset requires confirmation text: "
                    + RESET_CONFIRMATION_TEXT);
        }
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
    private SnapshotData snapshotData(String period) {
        return snapshotData(window(period));
    }

    private SnapshotData snapshotData(TimeWindow window) {
        MonitorSnapshot snapshot = monitorSnapshot(window);
        LlmDecisionSummary llm = llmSummary(window.from(), window.to());
        OperationsSummary operations = operationsSummary(window.from(), window.to());
        StandardMetrics metrics = standardMetrics(llm, operations);
        return new SnapshotData(
                window,
                snapshot,
                llm,
                operations,
                metrics,
                readinessRecommendation(llm, operations));
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
        return new MonitoringSessionCurrent(
                "current",
                format(currentSessionStart(data.window().generatedAt())),
                format(data.window().from()),
                format(data.window().to()),
                data.llm().totalDecisionCount(),
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
                               llm_mode, llm_provider, llm_model, prompt_template_version, policy_version,
                               llm_decision_count,
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
        RuntimeModeSummary runtimeModes = data.snapshot().runtimeModes();
        return new MonitoringSessionSummary(
                sessionId,
                format(data.window().from()),
                format(data.window().to()),
                data.window().period(),
                resetBy,
                reason,
                runtimeModes == null ? "UNKNOWN" : runtimeModes.llmMode(),
                firstBreakdownKey(data.llm().providerBreakdown()),
                firstBreakdownKey(data.llm().modelBreakdown()),
                firstBreakdownKey(data.llm().promptTemplateBreakdown()),
                currentPolicyVersion(),
                data.llm().totalDecisionCount(),
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
                            llm_mode, llm_provider, llm_model, prompt_template_version, policy_version,
                            llm_decision_count, failure_rate,
                            timeout_rate, parser_failure_rate, model_unavailable_rate,
                            average_latency_ms, p95_latency_ms, recommendation, top_blockers_json, summary_json
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                summary.sessionId(),
                LocalDateTime.parse(summary.startedAt(), ISO),
                LocalDateTime.parse(summary.endedAt(), ISO),
                summary.period(),
                summary.resetBy(),
                summary.resetReason(),
                summary.llmMode(),
                summary.llmProvider(),
                summary.llmModel(),
                summary.promptTemplateVersion(),
                summary.policyVersion(),
                summary.llmDecisionCount(),
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
        payload.put("llmDecisionCount", data.llm().totalDecisionCount());
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
        long llmDecisionCount = data.llm().totalDecisionCount();
        if (llmDecisionCount <= 0) {
            blockers.add(new ReadinessBlocker(
                    "NO_LLM_DECISION",
                    "No AI decision data",
                    "0",
                    "1 or more",
                    "Verify that Protectable requests reach AI decision logging."));
            return blockers;
        }
        MetricValue failureMetric = data.metrics().failureRate();
        double failureRate = metricNumber(failureMetric);
        if (failureMetric != null && failureMetric.value() != null && failureRate > 0.10d) {
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
                "select min(created_at) from ai_security_decision_observation");
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
            long deletedAi) {
        String details = "sessionId=" + sessionId
                + ", deletedAi=" + deletedAi;
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

    private StandardMetrics standardMetrics(
            LlmDecisionSummary llm,
            OperationsSummary operations) {
        long failures = operations.parserFailureCount()
                + operations.technicalFallbackCount()
                + operations.timeoutCount()
                + operations.modelUnavailableCount();

        return new StandardMetrics(
                countMetric("totalAiDecisions", "AI decisions", "Requests analyzed by AI.",
                        llm.totalDecisionCount()),
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
                summary.protectableDecisionCount(),
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

    private double metricNumber(MetricValue metric) {
        return metric == null || metric.value() == null ? 0.0d : metric.value();
    }

    private RuntimeModeSummary runtimeModeSummary() {
        SecurityZeroTrustProperties.SecurityMode llmMode = zeroTrustProperties == null
                ? SecurityZeroTrustProperties.SecurityMode.ENFORCE
                : zeroTrustProperties.getMode();
        return new RuntimeModeSummary(
                llmMode.name(),
                llmEffectKey(llmMode));
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
                        "trigger_source = 'PROTECTABLE' and created_at between ? and ?",
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

    private OperationsSummary operationsSummary(LocalDateTime from, LocalDateTime to) {
        long parserFailures = countAi(
                "parser_failure = true and created_at between ? and ?", from, to);
        long technicalFallbacks = countAi(
                "technical_fallback = true and created_at between ? and ?", from, to);
        long timeouts = countAi(
                "timeout_failure = true and created_at between ? and ?", from, to);
        long modelUnavailable = countAi(
                "model_unavailable = true and created_at between ? and ?", from, to);
        long providerThrottleWaits = countAi(
                "provider_throttle_wait_ms is not null and provider_throttle_wait_ms > 0 and created_at between ? and ?", from, to);
        return new OperationsSummary(
                averageAi("llm_latency_ms", from, to),
                parserFailures,
                technicalFallbacks,
                timeouts,
                modelUnavailable,
                providerThrottleWaits,
                latencyBreakdown(from, to));
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

    private String readinessRecommendation(
            LlmDecisionSummary llm,
            OperationsSummary operations) {
        if (llm.totalDecisionCount() <= 0) {
            return "INSUFFICIENT_DATA";
        }
        double failureRate = ratio(
                operations.parserFailureCount()
                        + operations.technicalFallbackCount()
                        + operations.timeoutCount()
                        + operations.modelUnavailableCount(),
                llm.totalDecisionCount());
        if (failureRate >= 0.10d) {
            return "DO_NOT_RECOMMEND";
        }
        return "KEEP_MONITORING";
    }
    private long countAi(String whereClause, Object... args) {
        return count("ai_security_decision_observation", whereClause + " and " + monitorablePath("request_path"), args);
    }

    private List<NamedCount> breakdownAi(String expression, LocalDateTime from, LocalDateTime to) {
        return breakdownWhere(
                "ai_security_decision_observation",
                expression,
                "created_at between ? and ? and " + monitorablePath("request_path"),
                from,
                to);
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
                latencyMetric("PROVIDER_THROTTLE_WAIT_MS", "providerThrottleWaitMs", from, to),
                latencyMetric("OPENAI_CALL_MS", "openAiCallMs", from, to),
                latencyMetric("PARSE_MS", "parseMs", from, to),
                latencyMetric("PERSIST_MS", "persistMs", from, to),
                latencyMetric("TOTAL_ANALYSIS_MS", "totalAnalysisMs", from, to));
    }

    private LatencyBreakdownMetric latencyMetric(String key, String jsonKey, LocalDateTime from, LocalDateTime to) {
        return new LatencyBreakdownMetric(
                key,
                averageLatencyMetadata(jsonKey, from, to),
                percentileLatencyMetadata(jsonKey, from, to, 0.95d),
                percentileLatencyMetadata(jsonKey, from, to, 0.99d));
    }

    private double averageLatencyMetadata(String jsonKey, LocalDateTime from, LocalDateTime to) {
        String columnName = latencyColumn(jsonKey);
        if (columnName == null) {
            return 0.0d;
        }
        return averageAi(columnName, from, to);
    }

    private double percentileLatencyMetadata(String jsonKey, LocalDateTime from, LocalDateTime to, double percentile) {
        String columnName = latencyColumn(jsonKey);
        if (columnName == null) {
            return 0.0d;
        }
        return percentileLatencyColumn(columnName, from, to, percentile);
    }

    private double p95LatencyColumn(String columnName, LocalDateTime from, LocalDateTime to) {
        return percentileLatencyColumn(columnName, from, to, 0.95d);
    }

    private double percentileLatencyColumn(String columnName, LocalDateTime from, LocalDateTime to, double percentile) {
        JdbcOperations jdbcOperations = jdbcOperations();
        if (jdbcOperations == null) {
            return 0.0d;
        }
        Double value = jdbcOperations.queryForObject(
                "select percentile_cont(" + percentile + ") within group (order by " + columnName + ") "
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
            case "providerThrottleWaitMs" -> "provider_throttle_wait_ms";
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

    private String message(Locale locale, String key) {
        Locale resolvedLocale = locale == null ? Locale.ENGLISH : locale;
        return messageSource.getMessage(key, null, key, resolvedLocale);
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
            LlmDecisionSummary llm,
            OperationsSummary operations,
            StandardMetrics metrics,
            String readinessRecommendation) {
    }
}


