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
package io.contexa.autoconfigure.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionOutputContract;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustConsoleRetention;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustCoverageCounter;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustDecisionOutcomes;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustHourlyStats;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustReviewSampler;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.sql.Date;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Console plan stage 2 on a real database: the console's columns, tables and indexes on a new database and on one
 * installed before them, and the SQL of the writer, the hourly tables, the coverage counts, the retention, the review
 * sample and the outcomes.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class ZeroTrustConsoleDataPostgresTest {

    private static final String SCHEMA = "META-INF/contexa/db/schema.sql";
    private static final List<String> CONSOLE_COLUMNS = List.of("attempt_kind", "original_event_id", "decision_stage",
            "analysis_depth", "decision_source", "decision_change_cause", "enforcement_result", "enforcement_timing",
            "actor_kind", "resource_class", "prompt_bundle_version", "prompt_content_hash", "most_likely_hypothesis",
            "context_coverage_level",
            "baseline_status", "unknown_fact_count", "prompt_tokens", "cached_prompt_tokens", "output_tokens",
            "model_call_count", "user_wait_ms", "decision_summary_json");
    private static final List<String> CONSOLE_TABLES = List.of("ctxa_zt_decision_reason", "ctxa_zt_decision_outcome",
            "ctxa_zt_stats_hourly", "ctxa_zt_coverage_hourly", "ctxa_zt_review_queue", "ctxa_zt_item_hourly",
            "ctxa_zt_latency_hourly");
    private static final List<String> CONSOLE_INDEXES = List.of("ctxa_idx_ai_sec_decision_user_created",
            "ctxa_idx_ai_sec_decision_request", "ctxa_idx_audit_log_timestamp", "ctxa_idx_audit_log_category_timestamp",
            "ctxa_idx_audit_log_correlation", "ctxa_idx_blocked_user_user_status", "ctxa_idx_zt_item_hourly_dimension",
            "ctxa_idx_zt_latency_hourly_bucket");

    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;

    private final MovableClock clock = new MovableClock(Instant.now().truncatedTo(ChronoUnit.HOURS).plus(Duration.ofMinutes(30)));
    private final SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();

    @BeforeAll
    static void aNewDatabase() throws Exception {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        install(database.dataSource());
    }

    @AfterAll
    static void close() {
        if (database != null) {
            database.close();
        }
    }

    @BeforeEach
    void emptyTables() {
        jdbc.execute("TRUNCATE ctxa_ai_security_decision_observation, ctxa_zt_decision_reason, ctxa_zt_decision_outcome, "
                + "ctxa_zt_stats_hourly, ctxa_zt_coverage_hourly, ctxa_zt_review_queue, ctxa_zt_item_hourly, "
                + "ctxa_zt_latency_hourly");
        properties.getConsole().setEnabled(true);
    }

    private static void install(DataSource dataSource) throws Exception {
        IamSeedDataAutoConfiguration.executeSchemaSql(dataSource, SCHEMA,
                IamSeedDataAutoConfiguration.sanitizeSchemaSqlForInstalledDatabase(
                        new ClassPathResource(SCHEMA).getContentAsString(StandardCharsets.UTF_8)));
    }

    @Test
    void aNewDatabaseHasTheConsoleColumnsTablesAndIndexes() {
        assertConsoleSchema(jdbc);
    }

    /** A database installed before the console gains its columns, tables and indexes from the start's maintenance. */
    @Test
    void aDatabaseInstalledBeforeTheConsoleGainsThemFromTheMaintenance() throws Exception {
        try (PostgresTestDatabase older = PostgresTestDatabase.empty()) {
            install(older.dataSource());
            JdbcTemplate olderJdbc = older.jdbcTemplate();
            olderJdbc.update("INSERT INTO ctxa_ai_security_decision_observation (observation_id, final_action) "
                    + "VALUES ('kept-row', 'ALLOW')");
            for (String column : CONSOLE_COLUMNS) {
                olderJdbc.execute("ALTER TABLE ctxa_ai_security_decision_observation DROP COLUMN " + column);
            }
            for (String table : CONSOLE_TABLES) {
                olderJdbc.execute("DROP TABLE " + table);
            }
            for (String index : CONSOLE_INDEXES) {
                // An index of a table dropped above went with it.
                olderJdbc.execute("DROP INDEX IF EXISTS " + index);
            }

            IamSeedDataAutoConfiguration.applyCanonicalSchemaMaintenance(older.dataSource(), null, false);

            assertConsoleSchema(olderJdbc);
            assertThat(olderJdbc.queryForObject("SELECT final_action FROM ctxa_ai_security_decision_observation "
                    + "WHERE observation_id = 'kept-row'", String.class)).as("the rows stay").isEqualTo("ALLOW");
            // K17: a review queue of an earlier version gains the reason at the next start.
            olderJdbc.execute("ALTER TABLE ctxa_zt_review_queue DROP COLUMN review_reason");
            // A second start finds everything in place and changes nothing.
            IamSeedDataAutoConfiguration.applyCanonicalSchemaMaintenance(older.dataSource(), null, false);
            assertConsoleSchema(olderJdbc);
        }
    }

    private static void assertConsoleSchema(JdbcTemplate target) {
        List<String> columns = target.queryForList("SELECT column_name FROM information_schema.columns "
                + "WHERE table_schema = current_schema() AND table_name = 'ctxa_ai_security_decision_observation'",
                String.class);
        assertThat(columns).containsAll(CONSOLE_COLUMNS);
        List<String> tables = target.queryForList("SELECT table_name FROM information_schema.tables "
                + "WHERE table_schema = current_schema()", String.class);
        assertThat(tables).containsAll(CONSOLE_TABLES);
        List<String> indexes = target.queryForList("SELECT indexname FROM pg_indexes WHERE schemaname = current_schema()",
                String.class);
        assertThat(indexes).containsAll(CONSOLE_INDEXES);
        // K17: why a decision waits for review
        assertThat(target.queryForList("SELECT column_name FROM information_schema.columns WHERE table_schema = "
                + "current_schema() AND table_name = 'ctxa_zt_review_queue'", String.class)).contains("review_reason");
    }

    /** The decision row and its reason rows are written by one statement, so a reason never lacks its decision. */
    @Test
    void theWriterKeepsTheConsoleColumnsAndTheReasonRowsInOneStatement() {
        AiSecurityDecisionObservationWriter writer = new AiSecurityDecisionObservationWriter(
                () -> jdbc, new ObjectMapper(), "ollama", "qwen");
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-1")
                .userId("alice")
                .metadata(Map.of("requestId", "request-1", "protectableDeclared", true,
                        "executionSubjectKind", "HUMAN", "protectableSync", true,
                        "promptBundleSelection.version", "v2.0",
                        "promptBundleSelection.contentHash", "c".repeat(64),
                        "modelCallStages", List.of("LAYER1", "LAYER2")))
                .build();
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action(ZeroTrustAction.CHALLENGE.name())
                .reasoning("A device and a network the user never used.")
                .reasonCodes(List.of(new SecurityDecisionOutputContract.Citation("DEVIATION_DEVICE", "F3"),
                        new SecurityDecisionOutputContract.Citation("DEVIATION_NETWORK", "F4")))
                .llmDecisionPresent(true)
                .build();

        String observationId = writer.recordDecision(event, result, ZeroTrustAction.CHALLENGE);

        Map<String, Object> row = jdbc.queryForMap("SELECT attempt_kind, decision_source, enforcement_timing, actor_kind, "
                + "prompt_bundle_version, prompt_content_hash, model_call_count, decision_summary_json "
                + "FROM ctxa_ai_security_decision_observation WHERE observation_id = ?", observationId);
        assertThat(row).containsEntry("attempt_kind", "FIRST").containsEntry("decision_source", "MODEL")
                .containsEntry("enforcement_timing", "BEFORE_RESPONSE").containsEntry("actor_kind", "HUMAN")
                .containsEntry("prompt_bundle_version", "v2.0").containsEntry("model_call_count", 2)
                // Plan 3.7: the version the decision ran is named v2.0, beside its content hash.
                .containsEntry("prompt_content_hash", "c".repeat(64));
        assertThat(String.valueOf(row.get("decision_summary_json"))).contains("DEVIATION_DEVICE");
        List<Map<String, Object>> reasons = jdbc.queryForList("SELECT reason_rank, reason_code, fact_id "
                + "FROM ctxa_zt_decision_reason WHERE observation_id = ? ORDER BY reason_rank", observationId);
        assertThat(reasons).extracting(each -> each.get("reason_code"))
                .containsExactly("DEVIATION_DEVICE", "DEVIATION_NETWORK");
        assertThat(reasons).extracting(each -> each.get("fact_id")).containsExactly("F3", "F4");
    }

    /**
     * K21: the row's mode is the Zero Trust mode the enforcement handler states, not the LLM step's runtime-selection
     * label kept under the same key (a real SHADOW run with a thinking-disabled model wrote that label).
     */
    @Test
    void theRowsModeIsTheZeroTrustModeNotTheLlmStepsLabel() {
        AiSecurityDecisionObservationWriter writer = new AiSecurityDecisionObservationWriter(
                () -> jdbc, new ObjectMapper(), "ollama", "qwen3:8b");
        ProcessingResult result = ProcessingResult.builder().success(true).action(ZeroTrustAction.ALLOW.name())
                .llmDecisionPresent(true).build();
        String shadow = writer.recordDecision(SecurityEvent.builder().eventId("event-shadow").userId("alice")
                .metadata(Map.of("requestId", "request-shadow", "decisionBoundaryMode", "RUNTIME_MODEL_SELECTION",
                        "runtimeEnforcementMode", "SHADOW")).build(), result, ZeroTrustAction.ALLOW);
        String stated = writer.recordDecision(SecurityEvent.builder().eventId("event-stated").userId("alice")
                .metadata(Map.of("requestId", "request-stated", "decisionBoundaryMode", "enforce")).build(),
                result, ZeroTrustAction.ALLOW);
        String none = writer.recordDecision(SecurityEvent.builder().eventId("event-none").userId("alice")
                .metadata(Map.of("requestId", "request-none", "decisionBoundaryMode", "RUNTIME_MODEL_SELECTION"))
                .build(), result, ZeroTrustAction.ALLOW);
        // a prompt shadow run copies its decision's metadata and states SHADOW: the stated boundary comes first
        String shadowRun = writer.recordDecision(SecurityEvent.builder().eventId("event-run").userId("alice")
                .metadata(Map.of("requestId", "request-run", "decisionBoundaryMode", "SHADOW",
                        "runtimeEnforcementMode", "ENFORCE")).build(), result, ZeroTrustAction.ALLOW);

        assertThat(mode(shadow)).isEqualTo("SHADOW");
        assertThat(mode(stated)).isEqualTo("ENFORCE");
        assertThat(mode(shadowRun)).isEqualTo("SHADOW");
        assertThat(mode(none)).as("no Zero Trust mode stated: no mode, not the LLM step's label").isNull();
    }

    /** K21: a row written before the fix gets its Zero Trust mode from its metadata on the retention pass. */
    @Test
    void theRetentionSetsTheModeOfAnOlderRowFromItsMetadata() {
        decision("before-fix", clock.instant().minus(Duration.ofHours(3)), "FIRST", "ALLOW", null, null);
        decision("outside", clock.instant().minus(Duration.ofDays(200)), "FIRST", "ALLOW", null, null);
        jdbc.update("UPDATE ctxa_ai_security_decision_observation SET decision_boundary_mode = 'RUNTIME_MODEL_SELECTION', "
                + "metadata_json = '{\"decisionBoundaryMode\":\"RUNTIME_MODEL_SELECTION\",\"runtimeEnforcementMode\":"
                + "\"ENFORCE\"}' WHERE observation_id IN ('before-fix', 'outside')");

        new ZeroTrustConsoleRetention(() -> jdbc, properties, clock).purgeOnce();

        assertThat(mode("before-fix")).isEqualTo("ENFORCE");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM ctxa_ai_security_decision_observation "
                + "WHERE observation_id = 'outside'", Long.class)).as("past the retention: removed, not repaired").isZero();
    }

    private static String mode(String observationId) {
        return jdbc.queryForObject("SELECT decision_boundary_mode FROM ctxa_ai_security_decision_observation "
                + "WHERE observation_id = ?", String.class, observationId);
    }

    /** A stricter action kept over the model's makes the engine the source of the action in force. */
    @Test
    void theEnforcementResultReachesItsRow() {
        AiSecurityDecisionObservationWriter writer = new AiSecurityDecisionObservationWriter(
                () -> jdbc, new ObjectMapper(), "ollama", "qwen");
        decision("applied", Instant.now(), "FIRST", "CHALLENGE", null, null);
        decision("kept", Instant.now(), "FIRST", "ALLOW", null, null);

        writer.recordEnforcement("applied", "APPLIED");
        writer.recordEnforcement("kept", "KEPT_STRICTER");

        assertThat(jdbc.queryForMap("SELECT enforcement_result, decision_source FROM ctxa_ai_security_decision_observation "
                + "WHERE observation_id = 'applied'")).containsEntry("enforcement_result", "APPLIED")
                .containsEntry("decision_source", "MODEL");
        assertThat(jdbc.queryForMap("SELECT enforcement_result, decision_source, decision_change_cause "
                + "FROM ctxa_ai_security_decision_observation WHERE observation_id = 'kept'"))
                .containsEntry("enforcement_result", "KEPT_STRICTER").containsEntry("decision_source", "ENGINE_CHANGED")
                .containsEntry("decision_change_cause", "KEPT_STRICTER");
    }

    /** A retry, a re-judgement, a timeout, a rejection and a test run are no decisions of their own (design 5, G28). */
    @Test
    void theHourlyTableCountsFirstDecisionsOnly() {
        Instant at = clock.instant().minus(Duration.ofMinutes(10));
        decision("first-allow", at, "FIRST", "ALLOW", null, null);
        decision("first-challenge", at, "FIRST", "CHALLENGE", null, null);
        decision("retry", at, "RETRY", "CHALLENGE", null, null);
        decision("again", at, "AGAIN", "CHALLENGE", null, null);
        decision("timeout", at, "TIMEOUT", "PENDING_ANALYSIS", null, null);
        decision("rejected", at, "REJECTED", "PENDING_ANALYSIS", null, null);
        decision("test-run", at, "FIRST", "BLOCK", null, "run-1");

        new ZeroTrustHourlyStats(() -> jdbc, properties, null, clock).rebuildOnce();

        assertThat(hourly("SUM(decision_count)", "final_action <> 'NO_DECISION'", hourOf(at))).isEqualTo(2L);
        assertThat(jdbc.queryForList("SELECT final_action FROM ctxa_zt_stats_hourly WHERE bucket_start = ?",
                String.class, Timestamp.from(hourOf(at))))
                .as("the timeout and the rejection got no decision of their request, one row for each failure")
                .containsExactlyInAnyOrder("ALLOW", "CHALLENGE", "NO_DECISION", "NO_DECISION");
        assertThat(jdbc.queryForList("SELECT decision_change_cause FROM ctxa_zt_stats_hourly "
                + "WHERE final_action = 'NO_DECISION'", String.class)).containsExactlyInAnyOrder("TIMEOUT", "REJECTED");
        assertThat(hourly("SUM(decision_count)", "final_action = 'NO_DECISION'", hourOf(at))).isEqualTo(2L);
        assertThat(jdbc.queryForObject("SELECT SUM(measured) FROM ctxa_zt_latency_hourly WHERE stage = 'TOTAL'",
                Long.class)).as("the latency of the decisions only").isEqualTo(2L);
        assertThat(jdbc.queryForObject("SELECT SUM(counted) FROM ctxa_zt_item_hourly WHERE dimension = 'USER'",
                Long.class)).isEqualTo(2L);
    }

    /** Console plan 5-2 ①②: the decisions by provider and model, and by what started their analysis. */
    @Test
    void theHourlyItemsCountTheProvidersAndTheTriggersOfTheDecisions() {
        Instant at = clock.instant().minus(Duration.ofMinutes(10));
        decision("ollama-1", at, "FIRST", "ALLOW", null, null);
        decision("ollama-2", at, "FIRST", "CHALLENGE", null, null);
        decision("openai-1", at, "FIRST", "ALLOW", null, null);
        decision("unknown-1", at, "FIRST", "BLOCK", null, null);
        decision("retry", at, "RETRY", "CHALLENGE", null, null);
        jdbc.update("UPDATE ctxa_ai_security_decision_observation SET model_provider = 'ollama', model_id = 'qwen3:8b', "
                + "trigger_source = 'PROTECTABLE' WHERE observation_id IN ('ollama-1', 'ollama-2', 'retry')");
        jdbc.update("UPDATE ctxa_ai_security_decision_observation SET model_provider = 'openai', model_id = 'gpt-x', "
                + "trigger_source = 'AUTHZEN' WHERE observation_id = 'openai-1'");

        new ZeroTrustHourlyStats(() -> jdbc, properties, null, clock).rebuildOnce();

        assertThat(jdbc.queryForList("SELECT item || ' ' || detail || ' ' || counted FROM ctxa_zt_item_hourly "
                + "WHERE dimension = 'PROVIDER' ORDER BY item COLLATE \"C\"", String.class))
                .as("the decisions only, a provider nothing recorded as UNKNOWN")
                .containsExactly("UNKNOWN  1", "ollama qwen3:8b 2", "openai gpt-x 1");
        assertThat(jdbc.queryForList("SELECT item || ' ' || counted FROM ctxa_zt_item_hourly "
                + "WHERE dimension = 'TRIGGER' ORDER BY item", String.class))
                .containsExactly("AUTHZEN 1", "PROTECTABLE 2", "UNKNOWN 1");
    }

    /** A timeout whose request was decided on a later try is no failure: the request got its decision. */
    @Test
    void aTimeoutWhoseRequestWasDecidedIsNoFailure() {
        Instant at = clock.instant().minus(Duration.ofMinutes(10));
        decision("timed-out", at, "TIMEOUT", "PENDING_ANALYSIS", "request-t", null);
        jdbc.update("UPDATE ctxa_ai_security_decision_observation SET event_id = 'event-t'");
        decision("decided-later", at.plusSeconds(30), "FIRST", "CHALLENGE", "request-t", null);
        jdbc.update("UPDATE ctxa_ai_security_decision_observation SET event_id = 'event-t' "
                + "WHERE observation_id = 'decided-later'");

        new ZeroTrustHourlyStats(() -> jdbc, properties, null, clock).rebuildOnce();

        assertThat(hourly("SUM(decision_count)", "final_action = 'NO_DECISION'", hourOf(at))).isZero();
        assertThat(hourly("SUM(decision_count)", "final_action = 'CHALLENGE'", hourOf(at))).isEqualTo(1L);
    }

    /** A release days after its block reaches the hour of the block, beyond the hours a run rebuilds by itself. */
    @Test
    void aLateOutcomeReachesTheHourOfItsDecision() {
        Instant blockedAt = clock.instant().minus(Duration.ofDays(3));
        decision("old-block", blockedAt, "FIRST", "BLOCK", "request-old", null);
        ZeroTrustHourlyStats stats = new ZeroTrustHourlyStats(() -> jdbc, properties, null, clock);
        stats.rebuildOnce();
        assertThat(hourly("COUNT(*)", hourOf(blockedAt))).as("beyond the first run's hours").isZero();

        clock.move(Duration.ofMinutes(5));
        new ZeroTrustDecisionOutcomes(() -> jdbc, clock).record("request-old", "alice", null,
                ZeroTrustDecisionOutcomes.Kind.ADMIN_RELEASED, "admin", "released");
        clock.move(Duration.ofMinutes(1));
        stats.rebuildOnce();

        assertThat(hourly("SUM(admin_released_count)", hourOf(blockedAt))).isEqualTo(1L);
        assertThat(hourly("SUM(decision_count)", hourOf(blockedAt))).isEqualTo(1L);
    }

    /**
     * K88: the hours a database kept before the unreviewed blocks, the code requests and the release times were counted
     * (their columns came in at zero) are rebuilt once by the first run after a start; an hour rebuilt is not again.
     */
    @Test
    void theHoursKeptBeforeTheNewColumnsAreRebuiltOnce() {
        Instant decidedAt = clock.instant().minus(Duration.ofDays(3));
        MovableClock then = new MovableClock(decidedAt.plus(Duration.ofMinutes(5)));
        decision("old-block", decidedAt, "FIRST", "BLOCK", "request-old-block", null);
        decision("old-released", decidedAt, "FIRST", "BLOCK", "request-old-released", null);
        decision("old-challenge", decidedAt, "FIRST", "CHALLENGE", "request-old-challenge", null);
        ZeroTrustDecisionOutcomes outcomes = new ZeroTrustDecisionOutcomes(() -> jdbc, then);
        outcomes.record("request-old-released", "alice", null, ZeroTrustDecisionOutcomes.Kind.ADMIN_RELEASED, "admin",
                "released");
        outcomes.record("request-old-challenge", "alice", null,
                ZeroTrustDecisionOutcomes.Kind.CHALLENGE_CODE_REQUESTED, "alice", null);
        new ZeroTrustHourlyStats(() -> jdbc, properties, null, then).rebuildOnce();
        assertThat(hourly("SUM(block_unreviewed_count)", hourOf(decidedAt))).isEqualTo(1L);
        // the hour as a database installed before the columns kept it: they came in at zero
        jdbc.update("UPDATE ctxa_zt_stats_hourly SET block_unreviewed_count = 0, challenge_code_requested_count = 0, "
                + "release_le_15m = 0, release_le_30m = 0, release_le_1h = 0, release_le_2h = 0, release_le_4h = 0, "
                + "release_le_8h = 0, release_le_24h = 0, release_le_72h = 0, release_le_7d = 0, release_gt_7d = 0, "
                + "computed_at = ? WHERE bucket_start = ?", Timestamp.from(then.instant()),
                Timestamp.from(hourOf(decidedAt)));

        new ZeroTrustHourlyStats(() -> jdbc, properties, null, clock).rebuildOnce();

        assertThat(hourly("SUM(block_unreviewed_count)", hourOf(decidedAt))).isEqualTo(1L);
        assertThat(hourly("SUM(challenge_code_requested_count)", hourOf(decidedAt))).isEqualTo(1L);
        assertThat(hourly("SUM(release_le_15m + release_le_30m + release_le_1h + release_le_2h + release_le_4h "
                + "+ release_le_8h + release_le_24h + release_le_72h + release_le_7d + release_gt_7d)",
                hourOf(decidedAt))).isEqualTo(1L);
        assertThat(hourly("SUM(decision_count)", hourOf(decidedAt))).isEqualTo(3L);
        Timestamp corrected = jdbc.queryForObject("SELECT MAX(computed_at) FROM ctxa_zt_stats_hourly "
                + "WHERE bucket_start = ?", Timestamp.class, Timestamp.from(hourOf(decidedAt)));
        assertThat(corrected.toInstant()).isEqualTo(clock.instant());

        clock.move(Duration.ofMinutes(10));
        new ZeroTrustHourlyStats(() -> jdbc, properties, null, clock).rebuildOnce();

        assertThat(jdbc.queryForObject("SELECT MAX(computed_at) FROM ctxa_zt_stats_hourly WHERE bucket_start = ?",
                Timestamp.class, Timestamp.from(hourOf(decidedAt))))
                .as("the next start leaves the corrected hour as it is").isEqualTo(corrected);
    }

    /** An outcome recorded before its decision row was written meets the row once it is there. */
    @Test
    void anOutcomeBeforeItsDecisionRowMeetsItLater() {
        ZeroTrustDecisionOutcomes outcomes = new ZeroTrustDecisionOutcomes(() -> jdbc, clock);
        outcomes.record("request-late-row", "bob", null, ZeroTrustDecisionOutcomes.Kind.UNBLOCK_REQUESTED, "bob", null);
        assertThat(jdbc.queryForObject("SELECT observation_id FROM ctxa_zt_decision_outcome", String.class)).isNull();
        Instant decidedAt = clock.instant().minus(Duration.ofMinutes(1));
        decision("late-row", decidedAt, "FIRST", "BLOCK", "request-late-row", null);

        new ZeroTrustHourlyStats(() -> jdbc, properties, null, clock).rebuildOnce();

        assertThat(jdbc.queryForObject("SELECT observation_id FROM ctxa_zt_decision_outcome", String.class))
                .isEqualTo("late-row");
        assertThat(hourly("SUM(unblock_requested_count)", hourOf(decidedAt))).isEqualTo(1L);
    }

    /** A challenge the request met and nobody answered in its time expired; a shadow one asked nobody. */
    @Test
    void anUnansweredChallengeExpires() {
        Instant askedAt = clock.instant().minus(ZeroTrustAction.CHALLENGE.getDefaultTtl()).minus(Duration.ofMinutes(1));
        decision("unanswered", askedAt, "FIRST", "CHALLENGE", "request-u", null);
        jdbc.update("UPDATE ctxa_ai_security_decision_observation SET enforcement_result = 'APPLIED'");
        decision("shadow", askedAt, "FIRST", "CHALLENGE", "request-s", null);
        jdbc.update("UPDATE ctxa_ai_security_decision_observation SET enforcement_result = 'SHADOW' "
                + "WHERE observation_id = 'shadow'");
        decision("passed", askedAt, "FIRST", "CHALLENGE", "request-p", null);
        jdbc.update("UPDATE ctxa_ai_security_decision_observation SET enforcement_result = 'APPLIED' "
                + "WHERE observation_id = 'passed'");
        new ZeroTrustDecisionOutcomes(() -> jdbc, clock).record("passed", "request-p", "alice", null,
                ZeroTrustDecisionOutcomes.Kind.CHALLENGE_PASSED, null, "alice", null);
        decision("recent", clock.instant().minus(Duration.ofMinutes(1)), "FIRST", "CHALLENGE", "request-r", null);
        jdbc.update("UPDATE ctxa_ai_security_decision_observation SET enforcement_result = 'APPLIED' "
                + "WHERE observation_id = 'recent'");

        ZeroTrustHourlyStats stats = new ZeroTrustHourlyStats(() -> jdbc, properties, null, clock);
        stats.rebuildOnce();
        stats.rebuildOnce();

        assertThat(jdbc.queryForList("SELECT observation_id FROM ctxa_zt_decision_outcome "
                + "WHERE outcome_kind = 'CHALLENGE_EXPIRED'", String.class)).containsExactly("unanswered");
    }

    /** Each node adds its own counts, so the counts of the nodes add up, and a second interval adds to the first. */
    @Test
    void theCoverageCountsOfTheNodesAddUp() {
        ZeroTrustCoverageCounter nodeA = new ZeroTrustCoverageCounter(() -> jdbc, "node-a", clock);
        ZeroTrustCoverageCounter nodeB = new ZeroTrustCoverageCounter(() -> jdbc, "node-b", clock);
        nodeA.protectedCall();
        nodeA.protectedCall();
        nodeA.reused();
        nodeB.protectedCall();
        nodeB.skipped(ZeroTrustCoverageCounter.SESSION_ALREADY_IN_LINE);
        nodeA.flush();
        nodeB.flush();
        nodeA.protectedCall();
        nodeA.flush();

        assertThat(coverage("PROTECTED_CALL", "")).isEqualTo(4L);
        assertThat(coverage("REUSED", "")).isEqualTo(1L);
        assertThat(coverage("SKIPPED", ZeroTrustCoverageCounter.SESSION_ALREADY_IN_LINE)).isEqualTo(1L);
        assertThat(jdbc.queryForObject("SELECT COUNT(DISTINCT node_id) FROM ctxa_zt_coverage_hourly", Long.class))
                .isEqualTo(2L);
        assertThat(nodeA.pending(ZeroTrustCoverageCounter.Kind.PROTECTED_CALL)).as("nothing left to write").isZero();
    }

    @Test
    void retentionRemovesOnlyWhatIsPastItsDays() {
        Instant now = clock.instant();
        decision("old", now.minus(Duration.ofDays(91)), "FIRST", "ALLOW", null, null);
        decision("kept", now.minus(Duration.ofDays(10)), "FIRST", "ALLOW", null, null);
        jdbc.update("INSERT INTO ctxa_zt_decision_reason (observation_id, reason_rank, reason_code, created_at) "
                + "VALUES ('old', 1, 'DEVIATION_TIME', ?), ('kept', 1, 'DEVIATION_TIME', ?)",
                Timestamp.from(now.minus(Duration.ofDays(91))), Timestamp.from(now.minus(Duration.ofDays(10))));
        jdbc.update("INSERT INTO ctxa_zt_coverage_hourly (bucket_start, node_id, counter_kind, counted) "
                + "VALUES (?, 'n', 'PROTECTED_CALL', 1), (?, 'n', 'PROTECTED_CALL', 1)",
                Timestamp.from(hourOf(now.minus(Duration.ofDays(731)))), Timestamp.from(hourOf(now.minus(Duration.ofDays(91)))));

        long removed = new ZeroTrustConsoleRetention(() -> jdbc, properties, clock).purgeOnce();

        assertThat(removed).isEqualTo(3L);
        assertThat(jdbc.queryForList("SELECT observation_id FROM ctxa_ai_security_decision_observation", String.class))
                .containsExactly("kept");
        assertThat(jdbc.queryForList("SELECT observation_id FROM ctxa_zt_decision_reason", String.class))
                .containsExactly("kept");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM ctxa_zt_coverage_hourly", Long.class))
                .as("an aggregate keeps two years").isEqualTo(1L);
    }

    /** The day's sample is drawn from the stopped first decisions, once, up to the daily number. */
    @Test
    void theReviewQueueDrawsUpToTheDailySampleOnce() {
        LocalDate day = LocalDate.now(clock.withZone(ZoneOffset.UTC)).minusDays(1);
        Instant noon = day.atTime(12, 0).toInstant(ZoneOffset.UTC);
        for (int i = 0; i < 25; i++) {
            decision("stopped-" + i, noon, "FIRST", i % 2 == 0 ? "CHALLENGE" : "BLOCK", null, null);
        }
        decision("allowed", noon, "FIRST", "ALLOW", null, null);
        decision("retried", noon, "RETRY", "BLOCK", null, null);
        decision("tested", noon, "FIRST", "BLOCK", null, "run-1");
        ZeroTrustReviewSampler sampler = new ZeroTrustReviewSampler(() -> jdbc, properties, clock);

        assertThat(sampler.sample(day)).isEqualTo(20);
        assertThat(sampler.sample(day)).as("the day's sample is complete").isZero();
        assertThat(jdbc.queryForList("SELECT observation_id FROM ctxa_zt_review_queue", String.class))
                .hasSize(20).allMatch(id -> id.startsWith("stopped-"));
    }

    /** An outcome finds the request's latest successful decision; an evaluation keeps its reason. */
    @Test
    void anOutcomeFindsTheLatestDecisionOfItsRequest() {
        decision("earlier", clock.instant().minus(Duration.ofMinutes(5)), "FIRST", "CHALLENGE", "request-x", null);
        decision("later", clock.instant().minus(Duration.ofMinutes(1)), "AGAIN", "CHALLENGE", "request-x", null);
        ZeroTrustDecisionOutcomes outcomes = new ZeroTrustDecisionOutcomes(() -> jdbc, clock);

        outcomes.record("request-x", "alice", "tenant-1", ZeroTrustDecisionOutcomes.Kind.CHALLENGE_FAILED, "alice", null);
        outcomes.evaluate("earlier", "request-x", "alice", "tenant-1", false,
                ZeroTrustDecisionOutcomes.EvaluationReason.OVERREACTION, "admin", "too strict");

        assertThat(jdbc.queryForObject("SELECT observation_id FROM ctxa_zt_decision_outcome "
                + "WHERE outcome_kind = 'CHALLENGE_FAILED'", String.class)).isEqualTo("later");
        assertThat(jdbc.queryForMap("SELECT observation_id, evaluation_reason, note FROM ctxa_zt_decision_outcome "
                + "WHERE outcome_kind = 'EVALUATED_INVALID'")).containsEntry("observation_id", "earlier")
                .containsEntry("evaluation_reason", "OVERREACTION").containsEntry("note", "too strict");
    }

    /**
     * K17 (decision D11), quality gate Q5: every decision whose model answer still broke a decision rule after its
     * retry keeps the rule in its row and waits in the review queue for it; a decision without one does not, nor does
     * a test run. K22: every row keeps the time it took to store.
     */
    @Test
    void everyDecisionWhoseAnswerBrokeARuleIsKeptAndQueuedForReview() {
        AiSecurityDecisionObservationWriter writer = new AiSecurityDecisionObservationWriter(
                () -> jdbc, new ObjectMapper(), "ollama", "qwen3:8b");
        List<Map<String, Object>> breaches = List.of(Map.of("layer", "Layer1", "rule",
                "REQUIRED_BLOCK_BOUNDARY_ACTION_MISMATCH"));
        ProcessingResult result = ProcessingResult.builder().success(true).action(ZeroTrustAction.ALLOW.name())
                .reasonCodes(List.of(new SecurityDecisionOutputContract.Citation("DEVIATION_DEVICE", "F3")))
                .llmDecisionPresent(true).build();
        List<String> broken = new ArrayList<>();
        List<String> kept = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            broken.add(writer.recordDecision(SecurityEvent.builder().eventId("event-broken-" + i).userId("alice")
                    .metadata(Map.of("requestId", "request-broken-" + i,
                            PromptRuntimeTelemetrySupport.RULE_BREACHES, breaches)).build(),
                    result, ZeroTrustAction.ALLOW));
            kept.add(writer.recordDecision(SecurityEvent.builder().eventId("event-kept-" + i).userId("alice")
                    .metadata(Map.of("requestId", "request-kept-" + i)).build(), result, ZeroTrustAction.ALLOW));
        }
        String tested = writer.recordDecision(SecurityEvent.builder().eventId("event-tested").userId("alice")
                .metadata(Map.of("requestId", "request-tested", "testRunId", "run-1",
                        PromptRuntimeTelemetrySupport.RULE_BREACHES, breaches)).build(), result, ZeroTrustAction.ALLOW);

        Long keptRule = jdbc.queryForObject("SELECT COUNT(*) FROM ctxa_ai_security_decision_observation "
                + "WHERE observation_id IN (" + quoted(broken) + ") "
                + "AND CAST(decision_summary_json AS jsonb) -> 'ruleBreaches' -> 0 ->> 'rule' "
                + "= 'REQUIRED_BLOCK_BOUNDARY_ACTION_MISMATCH'", Long.class);
        assertThat(keptRule).as("the rule is kept in every row of a decision that broke it").isEqualTo(10L);
        assertThat(jdbc.queryForList("SELECT observation_id FROM ctxa_zt_review_queue WHERE review_reason = 'RULE_BREACH' "
                + "AND review_status = 'PENDING'", String.class)).as("every such decision waits for review, and only they")
                .containsExactlyInAnyOrderElementsOf(broken).doesNotContain(tested);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM ctxa_ai_security_decision_observation "
                + "WHERE decision_summary_json LIKE '%ruleBreaches%' AND observation_id IN (" + quoted(kept) + ")",
                Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM ctxa_zt_decision_reason WHERE observation_id IN ("
                + quoted(broken) + ")", Long.class)).as("the reason rows are written with them").isEqualTo(10L);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM ctxa_ai_security_decision_observation "
                + "WHERE persist_ms IS NOT NULL AND persist_ms >= 0", Long.class)).as("K22").isEqualTo(21L);
    }

    /** K17: a decision queued for the rule it broke is no part of its day's random sample. */
    @Test
    void theDailySampleIsDrawnApartFromTheDecisionsQueuedForABrokenRule() {
        LocalDate day = LocalDate.now(clock.withZone(ZoneOffset.UTC)).minusDays(1);
        Instant noon = day.atTime(12, 0).toInstant(ZoneOffset.UTC);
        for (int i = 0; i < 25; i++) {
            decision("stopped-" + i, noon, "FIRST", "CHALLENGE", null, null);
        }
        jdbc.update("INSERT INTO ctxa_zt_review_queue (observation_id, sample_day, review_reason) VALUES (?, ?, ?)",
                "stopped-0", Date.valueOf(day), AiSecurityDecisionObservationWriter.REVIEW_RULE_BREACH);

        assertThat(new ZeroTrustReviewSampler(() -> jdbc, properties, clock).sample(day)).isEqualTo(20);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM ctxa_zt_review_queue WHERE review_reason = 'SAMPLE'",
                Long.class)).isEqualTo(20L);
    }

    private static String quoted(List<String> ids) {
        return String.join(", ", ids.stream().map(id -> "'" + id + "'").toList());
    }

    private static void decision(String observationId, Instant createdAt, String attemptKind, String finalAction,
                                 String requestId, String testRunId) {
        jdbc.update("""
                INSERT INTO ctxa_ai_security_decision_observation
                    (observation_id, request_id, user_id, final_action, attempt_kind, decision_source, success,
                     test_run_id, total_analysis_ms, created_at)
                VALUES (?, ?, 'alice', ?, ?, 'MODEL', ?, ?, 1500, ?)
                """, observationId, requestId != null ? requestId : UUID.randomUUID().toString(), finalAction,
                attemptKind, !"PENDING_ANALYSIS".equals(finalAction), testRunId, Timestamp.from(createdAt));
    }

    private static Instant hourOf(Instant at) {
        return at.truncatedTo(ChronoUnit.HOURS);
    }

    private static Long hourly(String expression, Instant hour) {
        return hourly(expression, "final_action <> 'NO_DECISION'", hour);
    }

    private static Long hourly(String expression, String condition, Instant hour) {
        Long value = jdbc.queryForObject("SELECT " + expression + " FROM ctxa_zt_stats_hourly WHERE bucket_start = ? AND "
                + condition, Long.class, Timestamp.from(hour));
        return value == null ? 0L : value;
    }

    private static Long coverage(String kind, String reason) {
        return jdbc.queryForObject("SELECT COALESCE(SUM(counted), 0) FROM ctxa_zt_coverage_hourly "
                + "WHERE counter_kind = ? AND reason = ?", Long.class, kind, reason);
    }

    /** A clock the test moves. */
    private static final class MovableClock extends Clock {

        private Instant now;

        private MovableClock(Instant now) {
            this.now = now;
        }

        void move(Duration by) {
            now = now.plus(by);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return Clock.fixed(now, zone);
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
