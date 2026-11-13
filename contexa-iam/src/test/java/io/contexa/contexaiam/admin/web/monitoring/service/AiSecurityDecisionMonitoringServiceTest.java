/*
 * Copyright 2026 The Contexa Project
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.contexaiam.admin.web.monitoring.service;

import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.testsupport.TestStores;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.FailureSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.LlmDecisionSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.MonitoringResetRequest;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.MonitoringResetResponse;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.ReadinessBlocker;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.StaticMessageSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AiSecurityDecisionMonitoringServiceTest {

    private SingleConnectionDataSource dataSource;
    private JdbcTemplate jdbcTemplate;
    private AiSecurityDecisionMonitoringService service;

    @BeforeEach
    void setUp() throws SQLException {
        TestStores.Database database = TestStores.database();
        Connection connection = DriverManager.getConnection(database.url(), database.username(), database.password());
        dataSource = new SingleConnectionDataSource(connection, true);
        jdbcTemplate = new JdbcTemplate(dataSource);
        createTables();
        seedRows();
        service = new AiSecurityDecisionMonitoringService(() -> jdbcTemplate, new SecurityZeroTrustProperties());
    }

    @AfterEach
    void tearDown() {
        if (dataSource != null) dataSource.destroy();
    }

    @Test
    void llmSummaryExposesDecisionQualityMetrics() {
        LlmDecisionSummary summary = service.llm("day");

        assertThat(summary.totalDecisionCount()).isEqualTo(3L);
        assertThat(summary.protectableDecisionCount()).isEqualTo(3L);
        assertThat(summary.triggerSourceBreakdown()).extracting("key").containsExactly("PROTECTABLE");
        assertThat(summary.parserFailureRate()).isGreaterThan(0.0d);
        assertThat(summary.timeoutRate()).isGreaterThan(0.0d);
        assertThat(summary.averageLatencyMs()).isGreaterThan(0.0d);
        assertThat(summary.riskScoreDistribution()).extracting("key").contains("0.80-1.00", "UNKNOWN");
        assertThat(summary.promptTemplateBreakdown()).extracting("key").contains("security-decision-v1");
    }

    @Test
    void failuresExposeObservedFailureCauses() {
        FailureSummary summary = service.failures("day");

        assertThat(summary.explicitFailureBreakdown()).extracting("key")
                .containsExactlyInAnyOrder("TIMEOUT", "MODEL_UNAVAILABLE");
        assertThat(summary.explicitFailureBreakdown()).extracting("count").doesNotContain(0L);
    }

    @Test
    void readinessBlockersFollowTheRequestLanguageAndArchivesKeepEnglish() {
        StaticMessageSource messages = new StaticMessageSource();
        messages.addMessage("admin.aiMonitor.blocker.timeout", Locale.KOREAN, "AI 분석 시간 초과");
        messages.addMessage("admin.aiMonitor.blocker.timeout.action", Locale.KOREAN, "시간 제한을 점검");
        AiSecurityDecisionMonitoringService localized = new AiSecurityDecisionMonitoringService(
                () -> jdbcTemplate, new SecurityZeroTrustProperties(), messages);
        LocaleContextHolder.setLocale(Locale.KOREAN);
        try {
            ReadinessBlocker timeout = localized.readiness("day").blockers().stream()
                    .filter(blocker -> "TIMEOUT".equals(blocker.key()))
                    .findFirst()
                    .orElseThrow();
            assertThat(timeout.title()).isEqualTo("AI 분석 시간 초과");
            assertThat(timeout.action()).isEqualTo("시간 제한을 점검");

            MonitoringResetResponse response = localized.resetMonitoring(
                    new MonitoringResetRequest("language check", "RESET"), "admin");
            assertThat(response.archivedSummary().topBlockersJson()).contains("AI analysis timed out");
        } finally {
            LocaleContextHolder.resetLocaleContext();
        }
    }

    @Test
    void resetArchivesAndDeletesOnlyDecisionMonitoringObservations() {
        assertThatThrownBy(() -> service.resetMonitoring(
                new MonitoringResetRequest("test", "WRONG"), "admin"))
                .isInstanceOf(IllegalArgumentException.class);

        MonitoringResetResponse response = service.resetMonitoring(
                new MonitoringResetRequest("fresh verification", "RESET"), "admin");

        assertThat(response.deletedLlmObservationCount()).isEqualTo(4L);
        assertThat(response.archivedSummary().resetReason()).isEqualTo("fresh verification");
        assertThat(countRows("ctxa_ai_security_decision_observation")).isZero();
        assertThat(countRows("ctxa_ai_security_monitoring_session_summary")).isEqualTo(1L);
        assertThat(countRows("ctxa_audit_log")).isEqualTo(1L);
    }

    private void createTables() {
        jdbcTemplate.execute("""
                create temporary table ctxa_ai_security_decision_observation (
                    observation_id varchar(64), created_at timestamp, request_id varchar(128), user_id varchar(128),
                    trigger_source varchar(64), trigger_relation varchar(64), http_method varchar(16), request_path varchar(256),
                    final_action varchar(64), proposed_action varchar(64), model_provider varchar(64), model_id varchar(128),
                    prompt_template_key varchar(128), parser_failure boolean, technical_fallback boolean,
                    timeout_failure boolean, model_unavailable boolean, success boolean, failure_type varchar(128),
                    fallback_category varchar(128), llm_latency_ms bigint, llm_risk_score double precision,
                    llm_confidence double precision, queue_wait_ms bigint, prompt_build_ms bigint, rag_vector_ms bigint,
                    openai_call_ms bigint, parse_ms bigint, persist_ms bigint, provider_throttle_wait_ms bigint,
                    total_analysis_ms bigint
                )
                """);
        jdbcTemplate.execute("""
                create temporary table ctxa_ai_security_monitoring_session_summary (
                    session_id varchar(64), started_at timestamp, ended_at timestamp, period varchar(32),
                    reset_by varchar(128), reset_reason varchar(512), llm_mode varchar(32), llm_provider varchar(64),
                    llm_model varchar(128), prompt_template_version varchar(128), policy_version varchar(128),
                    llm_decision_count bigint, failure_rate double precision, timeout_rate double precision,
                    parser_failure_rate double precision, model_unavailable_rate double precision,
                    average_latency_ms double precision, p95_latency_ms double precision,
                    recommendation varchar(64), top_blockers_json varchar(4096), summary_json varchar(4096)
                )
                """);
        jdbcTemplate.execute("""
                create temporary table ctxa_audit_log (
                    id bigint generated by default as identity, timestamp timestamp default current_timestamp,
                    principal_name varchar(255), resource_identifier varchar(512), action varchar(128),
                    decision varchar(64), reason varchar(1024), details varchar(4096), outcome varchar(64),
                    event_category varchar(64), event_source varchar(128), request_uri varchar(2048)
                )
                """);
    }

    private void seedRows() {
        LocalDateTime now = LocalDateTime.now().minusMinutes(10);
        insertObservation("obs-1", now, "req-1", "/admin/risk", "BLOCK", false, false, false, false, null, null, 100L, 0.92d, 0.88d);
        insertObservation("obs-2", now, "req-2", "/admin/protected", "ALLOW", true, true, true, false, "TIMEOUT", "PARSER", 200L, null, null);
        insertObservation("obs-3", now, "req-3", "/admin/model", "ALLOW", false, false, false, true, "NO_RUNTIME_LLM_CLIENT", "MODEL", null, null, null);
        insertObservation("static-obs-1", now, "static-req-1", "/img/logo.png", "ALLOW", false, false, false, false, null, null, 50L, 0.01d, 0.95d);
    }

    private void insertObservation(
            String id, LocalDateTime createdAt, String requestId, String path, String action,
            boolean parserFailure, boolean technicalFallback, boolean timeout, boolean modelUnavailable,
            String failureType, String fallbackCategory, Long latency, Double risk, Double confidence) {
        jdbcTemplate.update("""
                insert into ctxa_ai_security_decision_observation (
                    observation_id, created_at, request_id, user_id, trigger_source, trigger_relation,
                    http_method, request_path, final_action, proposed_action, model_provider, model_id,
                    prompt_template_key, parser_failure, technical_fallback, timeout_failure, model_unavailable,
                    success, failure_type, fallback_category, llm_latency_ms, llm_risk_score, llm_confidence
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, id, createdAt, requestId, "admin", "PROTECTABLE", "NOT_APPLICABLE",
                "GET", path, action, action, "openai", "gpt-5-nano", "security-decision-v1",
                parserFailure, technicalFallback, timeout, modelUnavailable,
                !parserFailure && !technicalFallback && !timeout && !modelUnavailable,
                failureType, fallbackCategory, latency, risk, confidence);
    }

    private long countRows(String tableName) {
        Long count = jdbcTemplate.queryForObject("select count(*) from " + tableName, Long.class);
        return count == null ? 0L : count;
    }
}
