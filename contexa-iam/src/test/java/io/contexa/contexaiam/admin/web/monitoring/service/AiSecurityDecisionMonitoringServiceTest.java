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
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.CorrelationSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.FailureSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.LlmDecisionSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.MonitorSnapshot;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.MonitoringResetRequest;
import io.contexa.contexaiam.admin.web.monitoring.dto.AiMonitorDtos.MonitoringResetResponse;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.HcadSummary;
import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.Qualification;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AiSecurityDecisionMonitoringServiceTest {

    private JdbcTemplate jdbcTemplate;
    private AiSecurityDecisionMonitoringService service;

    @BeforeEach
    void setUp() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("org.h2.Driver");
        dataSource.setUrl("jdbc:h2:mem:ai-monitor-" + System.nanoTime()
                + ";MODE=PostgreSQL;DATABASE_TO_UPPER=false;DB_CLOSE_DELAY=-1");
        jdbcTemplate = new JdbcTemplate(dataSource);
        createTables();
        seedRows();

        HcadMonitoringService hcadMonitoringService = mock(HcadMonitoringService.class);
        when(hcadMonitoringService.summarize(eq("day"))).thenReturn(hcadSummary());
        when(hcadMonitoringService.summarize(any(String.class), any(LocalDateTime.class), any(LocalDateTime.class)))
                .thenReturn(hcadSummary());
        HcadProperties properties = new HcadProperties();
        properties.getPreTrigger().getQualification().setEstimatedLlmCallCostUsd(0.02d);
        service = new AiSecurityDecisionMonitoringService(
                hcadMonitoringService,
                () -> jdbcTemplate,
                properties,
                new SecurityZeroTrustProperties(),
                () -> null,
                () -> null);
    }

    @Test
    @DisplayName("LLM summary should expose trigger/action/model/template, failure rates, latency and score distributions")
    void llm_shouldExposeDecisionQualityMetrics() {
        LlmDecisionSummary summary = service.llm("day");

        assertThat(summary.totalDecisionCount()).isEqualTo(3L);
        assertThat(summary.hcadPreTriggerDecisionCount()).isEqualTo(1L);
        assertThat(summary.protectableDecisionCount()).isEqualTo(1L);
        assertThat(summary.parserFailureRate()).isGreaterThan(0.0d);
        assertThat(summary.timeoutRate()).isGreaterThan(0.0d);
        assertThat(summary.averageLatencyMs()).isGreaterThan(0.0d);
        assertThat(summary.riskScoreDistribution()).extracting("key").contains("0.80-1.00", "UNKNOWN");
        assertThat(summary.confidenceDistribution()).extracting("key").contains("0.80-1.00");
        assertThat(summary.promptTemplateBreakdown()).extracting("key").contains("security-decision-v1");
    }

    @Test
    @DisplayName("Correlation summary should expose matrix rows, trigger relations and recent decisions")
    void correlation_shouldExposeMatrixAndRecentDecisions() {
        CorrelationSummary summary = service.correlation("day");

        assertThat(summary.triggerRelationBreakdown()).extracting("key")
                .contains("HCAD_ONLY", "PROTECTABLE_ONLY", "UNMATCHED_LLM");
        assertThat(summary.matrixRows()).extracting("key")
                .contains("HCAD_EARLY_TRIGGER", "HCAD_MISSED_OBSERVED", "HCAD_UNEVALUATED");
        assertThat(summary.matrixRows())
                .filteredOn(row -> "HCAD_EARLY_TRIGGER".equals(row.key()))
                .first()
                .satisfies(row -> assertThat(row.llmRiskCount()).isEqualTo(1L));
        assertThat(summary.recentCorrelations()).hasSize(3);
    }

    @Test
    @DisplayName("Failure summary should expose observed failure causes without fixed zero rows")
    void failures_shouldExposeExplicitFailureCauses() {
        FailureSummary summary = service.failures("day");

        assertThat(summary.explicitFailureBreakdown()).extracting("key")
                .containsExactlyInAnyOrder("TIMEOUT", "MODEL_UNAVAILABLE");
        assertThat(summary.explicitFailureBreakdown()).extracting("count")
                .doesNotContain(0L);
        assertThat(summary.failureTypeBreakdown()).extracting("key")
                .contains("TIMEOUT", "MODEL_UNAVAILABLE");
    }

    @Test
    @DisplayName("Monitoring reset should archive summary, delete only telemetry, and write audit")
    void resetMonitoring_shouldArchiveAndClearTelemetryOnlyAfterConfirmation() {
        assertThatThrownBy(() -> service.resetMonitoring(
                new MonitoringResetRequest("test", false, "WRONG"), "admin"))
                .isInstanceOf(IllegalArgumentException.class);

        MonitoringResetResponse response = service.resetMonitoring(
                new MonitoringResetRequest("fresh verification", false, "RESET"), "admin");

        assertThat(response.deletedHcadEvaluationCount()).isEqualTo(3L);
        assertThat(response.deletedLlmObservationCount()).isEqualTo(4L);
        assertThat(response.deletedCorrelationCount()).isEqualTo(4L);
        assertThat(response.learningEvidenceReset()).isFalse();
        assertThat(response.archivedSummary().resetReason()).isEqualTo("fresh verification");
        assertThat(countRows("hcad_detection_evaluation")).isZero();
        assertThat(countRows("ai_security_decision_observation")).isZero();
        assertThat(countRows("hcad_llm_decision_correlation")).isZero();
        assertThat(countRows("ai_security_monitoring_session_summary")).isEqualTo(1L);
        assertThat(countRows("audit_log")).isEqualTo(1L);
    }


    private void createTables() {
        jdbcTemplate.execute("""
                create table ai_security_decision_observation (
                    observation_id varchar(64),
                    created_at timestamp,
                    request_id varchar(128),
                    user_id varchar(128),
                    trigger_source varchar(64),
                    trigger_relation varchar(64),
                    http_method varchar(16),
                    request_path varchar(256),
                    final_action varchar(64),
                    proposed_action varchar(64),
                    model_provider varchar(64),
                    model_id varchar(128),
                    prompt_template_key varchar(128),
                    parser_failure boolean,
                    technical_fallback boolean,
                    timeout_failure boolean,
                    model_unavailable boolean,
                    success boolean,
                    failure_type varchar(128),
                    fallback_category varchar(128),
                    llm_latency_ms bigint,
                    llm_risk_score double precision,
                    llm_confidence double precision
                )
                """);
        jdbcTemplate.execute("""
                create table hcad_llm_decision_correlation (
                    correlation_id varchar(64),
                    hcad_evaluation_id varchar(64),
                    llm_observation_id varchar(64),
                    event_id varchar(128),
                    request_id varchar(128),
                    user_id varchar(128),
                    trigger_relation varchar(64),
                    outcome_class varchar(64),
                    hcad_score integer,
                    hcad_band varchar(32),
                    hcad_eligible boolean,
                    llm_final_action varchar(64),
                    llm_proposed_action varchar(64),
                    llm_risk_score double precision,
                    llm_confidence double precision,
                    created_at timestamp,
                    decided_at timestamp
                )
                """);
        jdbcTemplate.execute("""
                create table hcad_detection_evaluation (
                    evaluation_id varchar(64),
                    created_at timestamp,
                    request_path varchar(256),
                    eligible boolean,
                    triggered_llm boolean,
                    decided_at timestamp,
                    duplicate_suppressed boolean,
                    duplicate_suppressed_count integer,
                    mode varchar(64),
                    reason_codes varchar(512),
                    semantic_evidence_explanation_json varchar(4096)
                )
                """);
        jdbcTemplate.execute("""
                create table ai_security_monitoring_session_summary (
                    session_id varchar(64), started_at timestamp, ended_at timestamp, period varchar(32),
                    reset_by varchar(128), reset_reason varchar(512), hcad_mode varchar(32), llm_mode varchar(32),
                    llm_provider varchar(64), llm_model varchar(128), embedding_provider varchar(64), embedding_model varchar(128),
                    prompt_template_version varchar(128), policy_version varchar(128), observed_request_count bigint,
                    hcad_candidate_count bigint, hcad_triggered_llm_count bigint, llm_decision_count bigint,
                    hcad_trigger_ai_decision_count bigint, non_hcad_ai_decision_count bigint, true_positive_count bigint,
                    false_positive_count bigint, observable_false_negative_count bigint, true_negative_count bigint,
                    unknown_count bigint, hcad_precision double precision, hcad_false_positive_rate double precision,
                    match_rate double precision, mismatch_rate double precision, observable_false_negative_rate double precision,
                    unknown_rate double precision, failure_rate double precision, timeout_rate double precision,
                    parser_failure_rate double precision, model_unavailable_rate double precision, average_latency_ms double precision,
                    p95_latency_ms double precision, recommendation varchar(64), top_blockers_json varchar(4096),
                    summary_json varchar(4096)
                )
                """);
        jdbcTemplate.execute("""
                create table audit_log (
                    id bigint generated by default as identity,
                    timestamp timestamp default current_timestamp,
                    principal_name varchar(255),
                    resource_identifier varchar(512),
                    action varchar(128),
                    decision varchar(64),
                    reason varchar(1024),
                    details varchar(4096),
                    outcome varchar(64),
                    event_category varchar(64),
                    event_source varchar(128),
                    request_uri varchar(2048)
                )
                """);
    }

    private long countRows(String tableName) {
        Long count = jdbcTemplate.queryForObject("select count(*) from " + tableName, Long.class);
        return count == null ? 0L : count;
    }


    private void seedRows() {
        LocalDateTime now = LocalDateTime.now().minusMinutes(10);
        jdbcTemplate.update("""
                insert into ai_security_decision_observation
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, "obs-1", now, "req-1", "admin", "HCAD_PRE_TRIGGER", "HCAD_ONLY",
                "GET", "/admin/risk", "BLOCK", "BLOCK",
                "ollama", "llama3", "security-decision-v1", false, false, false, false,
                true, null, null, 100L, 0.92d, 0.88d);
        jdbcTemplate.update("""
                insert into ai_security_decision_observation
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, "obs-2", now, "req-2", "admin", "PROTECTABLE", "PROTECTABLE_ONLY",
                "POST", "/admin/protected", "ALLOW", "ALLOW",
                "ollama", "llama3", "security-decision-v1", true, true, true, false,
                false, "TIMEOUT", "PARSER", 200L, null, null);
        jdbcTemplate.update("""
                insert into ai_security_decision_observation
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, "obs-3", now, "req-3", "admin", "PROTECTABLE", "UNMATCHED_LLM",
                "GET", "/admin/model", "ALLOW", "ALLOW",
                "ollama", "llama3", "security-decision-v1", false, false, false, true,
                false, "NO_RUNTIME_LLM_CLIENT", "MODEL", null, null, null);
        jdbcTemplate.update("""
                insert into ai_security_decision_observation
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, "static-obs-1", now, "static-req-1", "admin", "HCAD_PRE_TRIGGER", "HCAD_ONLY",
                "GET", "/img/logo.png", "ALLOW", "ALLOW",
                "ollama", "llama3", "security-decision-v1", false, false, false, false,
                true, null, null, 50L, 0.01d, 0.95d);

        jdbcTemplate.update("""
                insert into hcad_llm_decision_correlation
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, "corr-1", "eval-1", "obs-1", "event-1", "req-1", "admin",
                "HCAD_ONLY", "TP", 90, "HIGH", true, "BLOCK", "BLOCK", 0.92d, 0.88d, now, now);
        jdbcTemplate.update("""
                insert into hcad_llm_decision_correlation
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, "corr-2", "eval-2", "obs-2", "event-2", "req-2", "admin",
                "PROTECTABLE_ONLY", "TN", 10, "LOW", false, "ALLOW", "ALLOW", 0.05d, 0.9d, now, now);
        jdbcTemplate.update("""
                insert into hcad_llm_decision_correlation
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, "corr-3", null, "obs-3", "event-3", "req-3", "admin",
                "UNMATCHED_LLM", "UNKNOWN", null, null, null, "ALLOW", "ALLOW", null, null, now, now);
        jdbcTemplate.update("""
                insert into hcad_llm_decision_correlation
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, "static-corr-1", "static-1", "static-obs-1", "static-event-1", "static-req-1", "admin",
                "HCAD_ONLY", "FP", 5, "LOW", false, "ALLOW", "ALLOW", 0.01d, 0.95d, now, now);

        jdbcTemplate.update("""
                insert into hcad_detection_evaluation values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, "eval-1", now, "/admin/risk", true, false, null, false, 0, "SHADOW", null, null);
        jdbcTemplate.update("""
                insert into hcad_detection_evaluation values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, "eval-2", now, "/admin/protected", false, false, null, false, 0, "SHADOW", null, null);
        jdbcTemplate.update("""
                insert into hcad_detection_evaluation values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, "static-1", now, "/img/logo.png", false, false, null, false, 0, "SHADOW", null, null);
        jdbcTemplate.execute("alter table ai_security_decision_observation add column queue_wait_ms bigint");
        jdbcTemplate.execute("alter table ai_security_decision_observation add column prompt_build_ms bigint");
        jdbcTemplate.execute("alter table ai_security_decision_observation add column rag_vector_ms bigint");
        jdbcTemplate.execute("alter table ai_security_decision_observation add column openai_call_ms bigint");
        jdbcTemplate.execute("alter table ai_security_decision_observation add column parse_ms bigint");
        jdbcTemplate.execute("alter table ai_security_decision_observation add column persist_ms bigint");
        jdbcTemplate.execute("alter table ai_security_decision_observation add column total_analysis_ms bigint");
    }

    private HcadSummary hcadSummary() {
        return new HcadSummary(
                "day",
                LocalDateTime.now().minusDays(1).toString(),
                LocalDateTime.now().toString(),
                LocalDateTime.now().toString(),
                new MonitorSnapshot("day", LocalDateTime.now().minusDays(1).toString(), LocalDateTime.now().toString(),
                        LocalDateTime.now().toString(), null),
                "SHADOW",
                120L,
                240L,
                30L,
                70L,
                50L,
                0.25d,
                20L,
                2L,
                1L,
                30L,
                4L,
                10L,
                3L,
                8L,
                0.90d,
                0.03d,
                100.0d,
                2L,
                0.04d,
                0.20d,
                new Qualification(0.8d, 0.9d, 0.95d, 100, 0.02d),
                "SHADOW_STABLE",
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of());
    }
}
