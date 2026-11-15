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
package io.contexa.contexaiam.admin.web.zerotrust;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustCoverageCounter;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustDecisionOutcomes;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustHourlyStats;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Adoption;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.DecisionDetail;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.DecisionPage;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.DecisionRow;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Evaluation;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Impact;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Operations;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Overview;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Share;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Trust;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;

/**
 * Console plan stage 3 on a real database: every screen's numbers against decision rows whose numbers are known,
 * through the hourly tables the screens read, and the decision records with their cursor, detail and evaluation.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class ZeroTrustConsolePostgresTest {

    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;

    private final Instant now = Instant.now().truncatedTo(ChronoUnit.HOURS).plus(Duration.ofMinutes(30));
    private final Clock clock = Clock.fixed(now, ZoneId.systemDefault());
    private final SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
    private ZeroTrustConsoleService service;
    private ZeroTrustDecisionRecords records;
    private ZeroTrustDecisionOutcomes outcomes;

    @BeforeAll
    static void aDatabaseWithTheSchema() throws Exception {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        String schema = new ClassPathResource("META-INF/contexa/db/schema.sql").getContentAsString(StandardCharsets.UTF_8);
        // One script, as a new installation sends it.
        try (Connection connection = database.dataSource().getConnection();
             Statement statement = connection.createStatement()) {
            statement.setEscapeProcessing(false);
            statement.execute(schema);
        }
    }

    @AfterAll
    static void close() {
        if (database != null) {
            database.close();
        }
    }

    @BeforeEach
    void aWeekOfKnownDecisions() {
        jdbc.execute("TRUNCATE ctxa_ai_security_decision_observation, ctxa_zt_decision_reason, ctxa_zt_decision_outcome, "
                + "ctxa_zt_stats_hourly, ctxa_zt_item_hourly, ctxa_zt_latency_hourly, ctxa_zt_coverage_hourly, "
                + "ctxa_zt_review_queue");
        properties.setMode(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
        // An outcome is recorded before the screen reads it: a period ends at the moment it is read.
        outcomes = new ZeroTrustDecisionOutcomes(() -> jdbc, Clock.fixed(now.minusSeconds(60), ZoneId.systemDefault()));
        service = new ZeroTrustConsoleService(() -> jdbc, properties, null, new ObjectMapper(), () -> null, true, clock);
        records = new ZeroTrustDecisionRecords(() -> jdbc, outcomes, null, new ObjectMapper(), clock);

        Instant at = now.minus(Duration.ofHours(2));
        String[] baselines = {"ESTABLISHED", "ESTABLISHED", "ESTABLISHED", "ESTABLISHED", "PROVISIONAL", "NONE"};
        for (int i = 0; i < 6; i++) {
            decision(Map.of("observation_id", "allow-" + i, "user_id", "u" + (i + 1), "final_action", "ALLOW",
                    "baseline_status", baselines[i], "context_coverage_level", i < 2 ? "BUSINESS_AWARE" : "SCOPE_AWARE"),
                    at);
        }
        decision(Map.of("observation_id", "challenge-1", "user_id", "u1", "final_action", "CHALLENGE",
                "most_likely_hypothesis", "H2", "resource_class", "SENSITIVE", "request_path", "/api/export",
                "enforcement_timing", "BEFORE_RESPONSE", "user_wait_ms", 1500L, "request_id", "request-c1",
                "decision_summary_json", "{\"reasons\":[{\"code\":\"DEVIATION_DEVICE\",\"fact\":\"F3\",\"factValue\":"
                        + "\"Chrome on Windows\"}],\"hypotheses\":[{\"id\":\"H2\",\"assessment\":\"MOST_LIKELY\"}],"
                        + "\"unknown\":{\"Approval\":\"NOT_INTEGRATED\"},\"reason\":\"A device never used.\"}"), at);
        decision(Map.of("observation_id", "challenge-2", "user_id", "u2", "final_action", "CHALLENGE",
                "most_likely_hypothesis", "H2", "resource_class", "SENSITIVE", "request_path", "/api/export",
                "enforcement_timing", "BEFORE_RESPONSE", "user_wait_ms", 3000L), at);
        decision(Map.of("observation_id", "block-1", "user_id", "u3", "final_action", "BLOCK",
                "decision_source", "MODEL_LESS", "decision_change_cause", "CONTRACT_FALLBACK",
                "most_likely_hypothesis", "H3", "request_id", "request-b1"), at);
        decision(Map.of("observation_id", "escalate-1", "user_id", "u4", "final_action", "ESCALATE",
                "decision_source", "ENGINE_CHANGED", "decision_change_cause", "ESCALATE_PROTECTION"), at);
        // A try that timed out without a decision, and a retry of a decision kept: neither is a decision.
        decision(Map.of("observation_id", "timeout-1", "user_id", "u5", "final_action", "PENDING_ANALYSIS",
                "attempt_kind", "TIMEOUT", "success", false, "failure_type", "EVENT_TIMEOUT", "request_path", "/api/slow"),
                at);
        decision(Map.of("observation_id", "retry-1", "user_id", "u1", "final_action", "CHALLENGE",
                "attempt_kind", "RETRY"), at);
        reason("challenge-1", "DEVIATION_DEVICE", "F3", at);
        reason("challenge-2", "DEVIATION_DEVICE", "F4", at);
        outcomes.record("challenge-1", "request-c1", "u1", null, ZeroTrustDecisionOutcomes.Kind.CHALLENGE_PASSED,
                null, "u1", null);
        outcomes.record("block-1", "request-b1", "u3", null, ZeroTrustDecisionOutcomes.Kind.ADMIN_RELEASED, null,
                "admin", "known user");

        ZeroTrustCoverageCounter counter = new ZeroTrustCoverageCounter(() -> jdbc, "node-1", Clock.fixed(at,
                ZoneId.systemDefault()));
        for (int i = 0; i < 15; i++) {
            counter.protectedCall();
        }
        counter.reused();
        counter.reused();
        counter.skipped(ZeroTrustCoverageCounter.SESSION_ALREADY_IN_LINE);
        counter.flush();
        new ZeroTrustHourlyStats(() -> jdbc, properties, null, clock).rebuildOnce();
    }

    @Test
    void theOverviewCountsDecisionsOnlyAndTheCoverageOfTheProtectedCalls() {
        Overview overview = service.overview("week", null, null, null, Locale.ENGLISH);

        assertThat(overview.summary().decisions()).isEqualTo(10);
        assertThat(overview.summary().stopped()).isEqualTo(4);
        assertThat(overview.summary().challenges()).isEqualTo(2);
        assertThat(overview.summary().challengesPassed()).isEqualTo(1);
        assertThat(overview.summary().blocks()).isEqualTo(1);
        assertThat(overview.summary().blocksReleased()).isEqualTo(1);
        assertThat(overview.coverage().coverage().numerator()).isEqualTo(12);
        assertThat(overview.coverage().coverage().denominator()).isEqualTo(15);
        assertThat(overview.coverage().noDecision().value()).isEqualTo(4.0);
        assertThat(overview.coverage().noDecisionReasons()).extracting(Share::key)
                .contains("REUSED", "SESSION_ALREADY_IN_LINE", "TECHNICAL_FAILURE");
        assertThat(overview.stopped().stopped().numerator()).isEqualTo(4);
        assertThat(overview.stopped().stopped().denominator()).isEqualTo(10);
        assertThat(overview.stopped().beforeResponse().numerator()).isEqualTo(2);
        assertThat(overview.impact().challengePass().metric().numerator()).isEqualTo(1);
        assertThat(overview.impact().challengePass().lower95()).isNotNull();
        assertThat(overview.trust().modelDecided().numerator()).isEqualTo(8);
        assertThat(overview.trust().modelLess().numerator()).isEqualTo(1);
        assertThat(overview.trust().baselineEstablished().numerator()).isEqualTo(4);
        assertThat(overview.trust().reviewValid().metric().value()).as("nothing reviewed").isNull();
        assertThat(overview.trust().reviewValid().metric().noDataReason()).isNotNull();
        assertThat(overview.trend()).hasSize(1);
        assertThat(overview.trend().get(0).noDecision()).isEqualTo(1);
        assertThat(overview.header().decisions()).isEqualTo(10);
        assertThat(overview.header().users()).isEqualTo(6);
        assertThat(overview.header().standalone()).isTrue();
    }

    @Test
    void aTenantsCoverageIsNotShown() {
        Overview overview = service.overview("week", null, null, "tenant-a", Locale.ENGLISH);

        assertThat(overview.coverage().coverage().value()).isNull();
        assertThat(overview.coverage().coverage().noDataReason()).isEqualTo(ZeroTrustConsoleMetrics.TENANT_FILTERED);
        assertThat(overview.summary().decisions()).as("no decision of that tenant").isZero();
        assertThat(overview.stopped().stopped().value()).as("no 0 for an empty denominator").isNull();
    }

    @Test
    void theImpactNamesWhatWasStoppedAndWhatItCost() {
        Impact impact = service.impact("week", null, null, null, Locale.ENGLISH);

        assertThat(impact.stopped().stopped()).isEqualTo(4);
        assertThat(impact.stopped().explained()).isEqualTo(3);
        assertThat(impact.stopped().hypotheses()).extracting(Share::key, Share::count)
                .contains(tuple("H2", 2L), tuple("H3", 1L));
        assertThat(impact.stopped().topReasons()).first().satisfies(item -> {
            assertThat(item.item()).isEqualTo("DEVIATION_DEVICE");
            assertThat(item.count()).isEqualTo(2);
            assertThat(item.note()).isEqualTo("DEVIATION");
        });
        assertThat(impact.stopped().topResources()).first().satisfies(item -> {
            assertThat(item.item()).isEqualTo("/api/export");
            assertThat(item.count()).isEqualTo(2);
        });
        assertThat(impact.cost().challenges().required()).isEqualTo(2);
        assertThat(impact.cost().challenges().passed()).isEqualTo(1);
        assertThat(impact.cost().challenges().codeRequests().noDataReason())
                .isEqualTo(ZeroTrustConsoleMetrics.NOT_RECORDED);
        assertThat(impact.cost().userWaitP50().value()).isBetween(1000.0, 2000.0);
        assertThat(impact.cost().userWaitP95().value()).isBetween(2000.0, 5000.0);
        assertThat(impact.cost().blocks().released()).isEqualTo(1);
        assertThat(impact.cost().blocks().releaseMedianHours().value()).isNotNull();
        assertThat(impact.cost().topChallengedUsers()).extracting(user -> user.user())
                .containsExactlyInAnyOrder("u1", "u2");
        assertThat(impact.cost().topChallengedUsers()).filteredOn(user -> "u1".equals(user.user())).first()
                .satisfies(user -> {
                    assertThat(user.passed()).isEqualTo(1);
                    assertThat(user.mainReason()).isEqualTo("DEVIATION_DEVICE");
                });
    }

    @Test
    void theTrustScreenSaysWhoSetTheActionAndOnWhatEvidence() {
        Trust trust = service.trust("week", null, null, null, Locale.ENGLISH);

        assertThat(trust.source().model().numerator()).isEqualTo(8);
        assertThat(trust.source().engineChanged().numerator()).isEqualTo(1);
        assertThat(trust.source().engineCauses()).extracting(Share::key).containsExactly("ESCALATE_PROTECTION");
        assertThat(trust.source().modelLessCauses()).extracting(Share::key).containsExactly("CONTRACT_FALLBACK");
        assertThat(trust.source().modelLessBlocks()).isEqualTo(1);
        assertThat(trust.evidence().baseline()).extracting(Share::key, Share::count).contains(
                tuple("ESTABLISHED", 4L),
                tuple("PROVISIONAL", 1L), tuple("NONE", 1L));
        assertThat(trust.evidence().users()).isEqualTo(6);
        assertThat(trust.evidence().unknownFacts()).first().satisfies(fact -> {
            assertThat(fact.fact()).isEqualTo("Approval");
            assertThat(fact.reason()).isEqualTo("NOT_INTEGRATED");
        });
        assertThat(trust.quality().contractFallback().numerator()).isEqualTo(1);
        assertThat(trust.changes()).hasSize(1);
    }

    @Test
    void theOperationsScreenReadsLatencyFailuresAndCost() {
        properties.getConsole().setPromptTokenPricePerMillion(1.0);
        properties.getConsole().setOutputTokenPricePerMillion(2.0);

        Operations operations = service.operations("week", null, null, null, Locale.ENGLISH);

        assertThat(operations.latency()).filteredOn(stage -> "TOTAL".equals(stage.stage())).first()
                .satisfies(stage -> {
                    assertThat(stage.measured()).isEqualTo(10);
                    assertThat(stage.p50Ms()).isBetween(1000L, 2000L);
                    assertThat(stage.averageMs()).as("console plan 5-2 ④: every decision took 1.5 s").isEqualTo(1500L);
                });
        // console plan 5-2 ①②: no provider was recorded; every decision came from a protected method
        assertThat(operations.providers()).singleElement().satisfies(provider -> {
            assertThat(provider.item()).isEqualTo("UNKNOWN");
            assertThat(provider.count()).isEqualTo(10);
            assertThat(provider.byDetail()).containsEntry("qwen3:8b", 10L);
        });
        assertThat(operations.triggers()).singleElement().satisfies(trigger -> {
            assertThat(trigger.key()).isEqualTo("PROTECTABLE");
            assertThat(trigger.count()).isEqualTo(10);
            assertThat(trigger.ratio()).isEqualTo(1.0);
        });
        assertThat(operations.failedPaths()).first().satisfies(path -> assertThat(path.item()).isEqualTo("/api/slow"));
        assertThat(operations.failureTrend()).hasSize(1);
        assertThat(operations.cost().tokensPerDecision().value()).isEqualTo(150.0);
        assertThat(operations.cost().costPerDay().value()).isNotNull();
        assertThat(operations.throughput().inLine()).as("no analysis line in this test").isNull();
    }

    @Test
    void theListReadsDecisionsByTimeWithACursorAndItsFilters() {
        Instant at = now.minus(Duration.ofHours(3));
        for (int i = 0; i < 50; i++) {
            decision(Map.of("observation_id", String.format("more-%02d", i), "final_action", "ALLOW"),
                    at.minusSeconds(i));
        }
        ZeroTrustConsoleRange week = service.range("week", null, null);

        DecisionPage first = records.list(week, null, null, null);
        DecisionPage second = records.list(week, null, null, first.nextCursor());

        assertThat(first.rows()).hasSize(ZeroTrustDecisionRecords.PAGE);
        assertThat(first.nextCursor()).isNotNull();
        assertThat(second.rows()).hasSize(10);
        assertThat(second.nextCursor()).isNull();
        assertThat(first.rows()).extracting(row -> row.observationId())
                .doesNotContainAnyElementsOf(second.rows().stream().map(row -> row.observationId()).toList());
        assertThat(records.list(week, null, new ZeroTrustDecisionRecords.Filter("CHALLENGE", null, null, null, null,
                null, null, null), null).rows()).hasSize(2);
        assertThat(records.list(week, null, new ZeroTrustDecisionRecords.Filter("NO_DECISION", null, null, null, null,
                null, null, null), null).rows()).extracting(row -> row.observationId()).containsExactly("timeout-1");
        assertThat(records.list(week, null, new ZeroTrustDecisionRecords.Filter(null, null, null, null, null,
                "ADMIN_RELEASED", null, null), null).rows()).extracting(row -> row.observationId())
                .containsExactly("block-1");
        assertThat(records.list(week, null, new ZeroTrustDecisionRecords.Filter(null, null, null, null, null, null,
                null, "/api/exp"), null).rows()).hasSize(2);
    }

    @Test
    void theDetailTellsTheConclusionTheReasonsAndWhatCameOfIt() {
        DecisionDetail detail = records.detail("challenge-1", Locale.ENGLISH);

        assertThat(detail.action()).isEqualTo("CHALLENGE");
        assertThat(detail.explained()).isTrue();
        assertThat(detail.reasons()).singleElement().satisfies(reason -> {
            assertThat(reason.code()).isEqualTo("DEVIATION_DEVICE");
            assertThat(reason.factValue()).isEqualTo("Chrome on Windows");
        });
        assertThat(detail.modelReason()).isEqualTo("A device never used.");
        assertThat(detail.hypotheses()).hasSize(1);
        assertThat(detail.unknown()).containsEntry("Approval", "NOT_INTEGRATED");
        assertThat(detail.outcomes()).extracting(outcome -> outcome.kind()).containsExactly("CHALLENGE_PASSED");
        assertThat(detail.conclusion()).contains("CHALLENGE").contains("DEVIATION").contains("CHALLENGE_PASSED");
        assertThat(detail.timings()).containsEntry("USER_WAIT", 1500L);
        assertThat(records.detail("missing", Locale.ENGLISH)).isNull();
    }

    @Test
    void anEvaluationIsKeptAsAnOutcomeAndClosesItsReview() {
        jdbc.update("INSERT INTO ctxa_zt_review_queue (observation_id, sample_day) VALUES ('block-1', CURRENT_DATE)");
        assertThat(records.reviewQueue()).extracting(item -> item.observationId()).containsExactly("block-1");

        records.evaluate("block-1", new Evaluation(false, "overreaction", "known user"), "admin");

        assertThat(jdbc.queryForMap("SELECT outcome_kind, evaluation_reason, actor FROM ctxa_zt_decision_outcome "
                + "WHERE observation_id = 'block-1' AND outcome_kind LIKE 'EVALUATED%'"))
                .containsEntry("outcome_kind", "EVALUATED_INVALID").containsEntry("evaluation_reason", "OVERREACTION")
                .containsEntry("actor", "admin");
        assertThat(records.reviewQueue()).isEmpty();
        assertThat(records.evaluate("missing", new Evaluation(true, null, null), "admin")).isNull();
        assertThatThrownBy(() -> records.evaluate("block-1", new Evaluation(null, null, null), "admin"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> records.evaluate("block-1", new Evaluation(false, "nonsense", null), "admin"))
                .isInstanceOf(IllegalArgumentException.class);

        new ZeroTrustHourlyStats(() -> jdbc, properties, null, clock).rebuildOnce();
        Trust trust = service.trust("week", null, null, null, Locale.ENGLISH);
        assertThat(trust.outcomes().reviewValid().metric().denominator()).isEqualTo(1);
        assertThat(trust.outcomes().invalidReasons()).extracting(Share::key).containsExactly("OVERREACTION");
    }

    /** Console decision 11.5: the three verdicts, by the criteria an operator set. */
    @Test
    void theAdoptionVerdictIsOneOfThree() {
        properties.setMode(SecurityZeroTrustProperties.EnforcementMode.SHADOW);
        Instant at = now.minus(Duration.ofHours(1));
        for (int i = 0; i < 4; i++) {
            decision(Map.of("observation_id", "shadow-" + i, "user_id", "s" + i, "final_action", i == 0 ? "BLOCK" : "ALLOW",
                    "decision_boundary_mode", "SHADOW", "baseline_status", "ESTABLISHED"), at);
        }
        outcomes.evaluate("shadow-0", null, "s0", null, true, null, "admin", null);
        new ZeroTrustHourlyStats(() -> jdbc, properties, null, clock).rebuildOnce();
        SecurityZeroTrustProperties.Adoption criteria = properties.getConsole().getAdoption();

        assertThat(service.adoption(null, Locale.ENGLISH).verdict()).as("too few decisions").isEqualTo("DATA_INSUFFICIENT");

        criteria.setMinObservedDays(1);
        criteria.setMinDecisions(4);
        criteria.setMinReviewSample(1);
        criteria.setMinReviewValidLowerBound(0.0);
        // Every decision was the model's, so a bound above 100% is the one criterion not met.
        criteria.setMinModelDecidedRatio(1.01);
        Adoption unmet = service.adoption(null, Locale.ENGLISH);
        assertThat(unmet.verdict()).isEqualTo("CONDITIONS_UNMET");
        assertThat(unmet.unmet()).isEqualTo(1);
        assertThat(unmet.criteria()).filteredOn(criterion -> "UNMET".equals(criterion.status()))
                .extracting(criterion -> criterion.key()).containsExactly("modelDecided");
        assertThat(unmet.wouldHave().stopped()).isEqualTo(1);
        assertThat(unmet.wouldHave().blockedAccounts()).isEqualTo(1);

        criteria.setMinModelDecidedRatio(0.95);
        Adoption recommended = service.adoption(null, Locale.ENGLISH);
        assertThat(recommended.criteria()).filteredOn(criterion -> !"INFO".equals(criterion.status()))
                .allSatisfy(criterion -> assertThat(criterion.status()).as(criterion.key()).isEqualTo("MET"));
        assertThat(recommended.verdict()).isEqualTo("RECOMMENDED");
    }

    /** Console plan 5-2 ③: the slowest decisions first, decisions only, as the AI monitor's slow requests. */
    @Test
    void theSlowestDecisionsComeFirst() {
        jdbc.update("UPDATE ctxa_ai_security_decision_observation SET total_analysis_ms = 9000 "
                + "WHERE observation_id IN ('challenge-2', 'retry-1', 'timeout-1')");
        jdbc.update("UPDATE ctxa_ai_security_decision_observation SET total_analysis_ms = 5000 "
                + "WHERE observation_id = 'block-1'");

        DecisionPage slowest = records.slowest(service.range("week", null, null), null, null);

        assertThat(slowest.nextCursor()).isNull();
        assertThat(slowest.rows()).hasSize(10);
        assertThat(slowest.rows()).extracting(DecisionRow::observationId).startsWith("challenge-2", "block-1")
                .doesNotContain("retry-1", "timeout-1");
        assertThat(slowest.rows().get(0).totalMs()).isEqualTo(9000L);
    }

    /** Console plan 5-2 ⑤: the AI monitor's past windows, newest first, for all tenants only. */
    @Test
    void theAiMonitorsPastWindowsAreShown() {
        jdbc.execute("TRUNCATE ctxa_ai_security_monitoring_session_summary");
        Instant end = now.minus(Duration.ofDays(3));
        for (String[] window : new String[][] {{"window-old", "10"}, {"window-new", "2"}}) {
            Instant ended = window[0].equals("window-new") ? end : end.minus(Duration.ofDays(Long.parseLong(window[1])));
            jdbc.update("INSERT INTO ctxa_ai_security_monitoring_session_summary (session_id, started_at, ended_at, "
                    + "llm_decision_count, failure_rate, timeout_rate, p95_latency_ms, recommendation, reset_by, "
                    + "reset_reason) VALUES (?, ?, ?, 120, 0.12, 0.04, 6400, 'DO_NOT_RECOMMEND', 'admin', 'trial')",
                    window[0], Timestamp.from(ended.minus(Duration.ofDays(1))), Timestamp.from(ended));
        }

        Adoption adoption = service.adoption(null, Locale.ENGLISH);

        assertThat(adoption.pastWindows()).hasSize(2);
        assertThat(adoption.pastWindows().get(0).endedAt()).isEqualTo(end.toString());
        assertThat(adoption.pastWindows().get(0)).satisfies(window -> {
            assertThat(window.decisions()).isEqualTo(120);
            assertThat(window.failureRate()).isEqualTo(0.12);
            assertThat(window.p95LatencyMs()).isEqualTo(6400.0);
            assertThat(window.recommendation()).isEqualTo("DO_NOT_RECOMMEND");
            assertThat(window.closedBy()).isEqualTo("admin");
        });
        assertThat(service.adoption("tenant-a", Locale.ENGLISH).pastWindows()).as("the windows have no tenant").isEmpty();
    }

    /** Console plan 5-4·5-5: the security event log and the blocked users open a request's decision by its request. */
    @Test
    void aRequestOpensItsFirstDecision() {
        decision(Map.of("observation_id", "challenge-1-again", "user_id", "u1", "final_action", "CHALLENGE",
                "attempt_kind", "RETRY", "request_id", "request-c1"), now.minus(Duration.ofMinutes(10)));

        assertThat(records.observationOfRequest("request-c1")).isEqualTo("challenge-1");
        assertThat(records.observationOfRequest("request-timeout-1")).isEqualTo("timeout-1");
        assertThat(records.observationOfRequest("request-nobody-sent")).isNull();
        assertThat(records.observationOfRequest(" ")).isNull();
    }

    private static void decision(Map<String, Object> values, Instant createdAt) {
        Map<String, Object> row = new HashMap<>(Map.ofEntries(
                Map.entry("event_id", "event-" + values.get("observation_id")),
                Map.entry("request_id", "request-" + values.get("observation_id")),
                Map.entry("user_id", "u0"), Map.entry("attempt_kind", "FIRST"), Map.entry("decision_source", "MODEL"),
                Map.entry("success", true), Map.entry("decision_boundary_mode", "ENFORCE"),
                Map.entry("trigger_source", "PROTECTABLE"), Map.entry("enforcement_timing", "NEXT_REQUEST"),
                Map.entry("prompt_bundle_version", "2026.11.15-v1.0"), Map.entry("model_id", "qwen3:8b"),
                Map.entry("total_analysis_ms", 1500L), Map.entry("llm_latency_ms", 1200L),
                Map.entry("prompt_tokens", 100L), Map.entry("output_tokens", 50L), Map.entry("model_call_count", 1),
                Map.entry("decision_stage", "LAYER1"), Map.entry("request_path", "/api/records")));
        row.putAll(values);
        row.put("created_at", Timestamp.from(createdAt));
        List<String> columns = List.copyOf(row.keySet());
        jdbc.update("INSERT INTO ctxa_ai_security_decision_observation (" + String.join(", ", columns) + ") VALUES ("
                + String.join(", ", columns.stream().map(column -> "?").toList()) + ")",
                columns.stream().map(row::get).toArray());
    }

    private static void reason(String observationId, String code, String fact, Instant at) {
        jdbc.update("INSERT INTO ctxa_zt_decision_reason (observation_id, reason_rank, reason_code, reason_group, fact_id, "
                + "created_at) VALUES (?, 1, ?, ?, ?, ?)", observationId, code, ZeroTrustConsoleService.groupOf(code), fact,
                Timestamp.from(at));
    }
}
