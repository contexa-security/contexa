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
        when(hcadMonitoringService.summarize(eq("day"), any(LocalDateTime.class), any(LocalDateTime.class)))
                .thenReturn(hcadSummary());
        HcadProperties properties = new HcadProperties();
        properties.getPreTrigger().getQualification().setEstimatedLlmCallCostUsd(0.02d);
        service = new AiSecurityDecisionMonitoringService(
                hcadMonitoringService,
                () -> jdbcTemplate,
                properties,
                new SecurityZeroTrustProperties());
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
                    reason_codes varchar(512)
                )
                """);
    }

    private void seedRows() {
        LocalDateTime now = LocalDateTime.now().minusMinutes(10);
        jdbcTemplate.update("""
                insert into ai_security_decision_observation
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, "obs-1", now, "req-1", "admin", "HCAD_PRE_TRIGGER", "HCAD_ONLY",
                "GET", "/admin/risk", "BLOCK", "BLOCK",
                "ollama", "llama3", "security-decision-v1", false, false, false, false,
                null, null, 100L, 0.92d, 0.88d);
        jdbcTemplate.update("""
                insert into ai_security_decision_observation
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, "obs-2", now, "req-2", "admin", "PROTECTABLE", "PROTECTABLE_ONLY",
                "POST", "/admin/protected", "ALLOW", "ALLOW",
                "ollama", "llama3", "security-decision-v1", true, true, true, false,
                "TIMEOUT", "PARSER", 200L, null, null);
        jdbcTemplate.update("""
                insert into ai_security_decision_observation
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, "obs-3", now, "req-3", "admin", "PROTECTABLE", "UNMATCHED_LLM",
                "GET", "/admin/model", "ALLOW", "ALLOW",
                "ollama", "llama3", "security-decision-v1", false, false, false, true,
                "NO_RUNTIME_LLM_CLIENT", "MODEL", null, null, null);
        jdbcTemplate.update("""
                insert into ai_security_decision_observation
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, "static-obs-1", now, "static-req-1", "admin", "HCAD_PRE_TRIGGER", "HCAD_ONLY",
                "GET", "/img/logo.png", "ALLOW", "ALLOW",
                "ollama", "llama3", "security-decision-v1", false, false, false, false,
                null, null, 50L, 0.01d, 0.95d);

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
                insert into hcad_detection_evaluation values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, "eval-1", now, "/admin/risk", true, false, null, false, 0, "SHADOW", null);
        jdbcTemplate.update("""
                insert into hcad_detection_evaluation values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, "eval-2", now, "/admin/protected", false, false, null, false, 0, "SHADOW", null);
        jdbcTemplate.update("""
                insert into hcad_detection_evaluation values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, "static-1", now, "/img/logo.png", false, false, null, false, 0, "SHADOW", null);
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
