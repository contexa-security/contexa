package io.contexa.showcase.portal.retention;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.combination.CombinationCatalog;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.security.SecureRandom;
import java.sql.Date;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * P5-PRV-02: one retention pass deletes exactly what the periods say, rows just inside a period stay, a visitor's hash
 * leaves every table with the visitor, and the pass records its counts. Retired and old draft recordings, runs that
 * nothing shows any more, the model usage ledger and retired or failed templates follow the data list
 * (docs/showcase/계획대조-검수.md N-7). Skipped without Docker.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest
class RetentionIntegrationTest {

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

    private static final String SIGNING_KEY = randomKey();
    private static final Instant NOW = Instant.parse("2026-10-05T12:00:00Z");
    private static final LocalDate TODAY = LocalDate.of(2026, 10, 5);
    private static final String OLD_VISITOR = "a".repeat(64);
    private static final String RECENT_VISITOR = "b".repeat(64);

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("showcase.internal.signing-key", () -> SIGNING_KEY);
    }

    @Autowired
    JdbcTemplate jdbc;

    @Autowired
    PlatformTransactionManager transactionManager;

    @Autowired
    ObjectMapper json;

    @Test
    void onePassDeletesExactlyWhatThePeriodsSayAndRecordsTheCounts() {
        world();
        RetentionJob job = new RetentionJob(new NamedParameterJdbcTemplate(jdbc),
                new TransactionTemplate(transactionManager), json, RetentionJob.Periods.plan(),
                Clock.fixed(NOW, ZoneOffset.UTC));

        RetentionJob.Pass pass = job.run();

        Map<String, Integer> expected = new LinkedHashMap<>();
        expected.put("visitors", 1);
        expected.put("runVisitorHashes", 1);
        expected.put("combinationVisitorHashes", 1);
        expected.put("predictionVisitorHashes", 1);
        expected.put("assessmentVisitorHashes", 1);
        expected.put("anonymousTallies", 1);
        expected.put("dailyQuota", 1);
        expected.put("allotmentAlerts", 1);
        expected.put("shareCards", 1);
        expected.put("supersededCombinations", 2);
        expected.put("retiredRecordings", 2);
        expected.put("oldRuns", 1);
        expected.put("costLedger", 1);
        expected.put("modelExchanges", 1);
        expected.put("retiredTemplates", 2);
        expected.put("retentionLog", 1);
        assertThat(pass.deleted()).containsExactlyEntriesOf(expected);

        assertThat(jdbc.queryForList("select visitor_hash from visitor", String.class)).containsExactly(RECENT_VISITOR);
        assertThat(jdbc.queryForList("select visitor_hash from visitor_journey", String.class))
                .as("the journey left with its visitor").containsExactly(RECENT_VISITOR);
        assertThat(jdbc.queryForList("select count from anonymous_tally", Long.class)).containsExactly(2L);
        assertThat(jdbc.queryForList("select run_id || ' ' || coalesce(visitor_hash, '-') from visitor_prediction "
                + "order by run_id", String.class)).as("the call stays, only the visitor's hash leaves (R-27)")
                .containsExactly("r-old -", "r-recent " + RECENT_VISITOR);
        assertThat(jdbc.queryForList("select run_id || ' ' || coalesce(visitor_hash, '-') from visitor_assessment "
                + "order by run_id", String.class)).containsExactly("r-old -", "r-recent " + RECENT_VISITOR);
        assertThat(jdbc.queryForList("select call_no from run_model_exchange order by call_no", Integer.class))
                .as("model call texts are kept 90 days").containsExactly(2);
        assertThat(jdbc.queryForList("select visitor_hash from prediction", String.class))
                .containsExactly(RECENT_VISITOR);
        assertThat(jdbc.queryForList("select coalesce(live_visitor_hash, '-') || ' ' || live_run from run "
                + "where run_id like 'r-%' order by run_id", String.class))
                .containsExactly("- true", RECENT_VISITOR + " true");
        assertThat(jdbc.queryForList("select run_id from run where run_id like 'ev-%' order by run_id", String.class))
                .as("an old run that a recording shows, an old one of a cell record and a recent one stay")
                .containsExactly("ev-cell", "ev-recent", "ev-shown");
        assertThat(jdbc.queryForList("select record_id from replay_record order by record_id", String.class))
                .containsExactly("rec-draft-new", "rec-published", "rec-retired-new");
        assertThat(jdbc.queryForList("select model from cost_ledger order by model", String.class))
                .containsExactly("recent");
        assertThat(jdbc.queryForList("select template_id from engine_template order by template_id", String.class))
                .as("the READY one, a recent retirement and an old one a kept run still refers to stay")
                .containsExactly("tpl-ready", "tpl-retired-new", "tpl-retired-used");
        assertThat(jdbc.queryForList("select combo_key || ':' || left(version_key, 1) from combination_record "
                + "order by 1", String.class)).containsExactly("V:v", "W:1", "W:2", "X:2", "Y:1");
        assertThat(jdbc.queryForObject("select count(*) from combination_record where visitor_hash = ?",
                Integer.class, OLD_VISITOR)).isZero();
        assertThat(jdbc.queryForList("select day from live_quota order by day", Date.class))
                .extracting(Date::toLocalDate).containsExactly(TODAY.minusDays(7), TODAY);
        assertThat(jdbc.queryForList("select day from live_allotment_alert", Date.class))
                .extracting(Date::toLocalDate).containsExactly(TODAY.minusDays(90));
        assertThat(jdbc.queryForList("select share_key from share_card", String.class)).containsExactly("RECENTKEY2");
        assertThat(job.recent(5)).hasSize(2);
        assertThat(String.valueOf(job.recent(1).get(0).get("deleted"))).contains("\"visitors\": 1");

        RetentionJob later = new RetentionJob(new NamedParameterJdbcTemplate(jdbc),
                new TransactionTemplate(transactionManager), json, RetentionJob.Periods.plan(),
                Clock.fixed(NOW.plusSeconds(60), ZoneOffset.UTC));
        assertThat(later.run().deleted().values()).as("a second pass has nothing left").allMatch(rows -> rows == 0);
        assertThat(later.recent(5)).hasSize(3);
    }

    @Test
    void theDailyPassRunsAtHalfPastThreeUtc() {
        assertThat(RetentionConfiguration.untilNext(Instant.parse("2026-10-05T03:00:00Z")))
                .isEqualTo(Duration.ofMinutes(30));
        assertThat(RetentionConfiguration.untilNext(Instant.parse("2026-10-05T03:30:00Z")))
                .isEqualTo(Duration.ofDays(1));
        assertThat(RetentionConfiguration.untilNext(Instant.parse("2026-10-05T04:00:00Z")))
                .isEqualTo(Duration.ofHours(23).plusMinutes(30));
    }

    private void world() {
        jdbc.update("insert into visitor (visitor_hash, first_seen_at, last_seen_at) values (?, ?, ?)", OLD_VISITOR,
                ago(40), ago(31));
        jdbc.update("insert into visitor (visitor_hash, first_seen_at, last_seen_at) values (?, ?, ?)", RECENT_VISITOR,
                ago(40), ago(29));
        jdbc.update("insert into prediction (visitor_hash, scene_key, choice) values (?, 'A3:ATTACK', 'BLOCK')",
                OLD_VISITOR);
        // The journey leaves with its visitor; the anonymous counts leave after the visitor period (ADR-35).
        for (String visitor : new String[]{OLD_VISITOR, RECENT_VISITOR}) {
            jdbc.update("insert into visitor_journey (visitor_hash, route, act, step, updated_at) "
                    + "values (?, 'DEFAULT', 1, 'scene', ?)", visitor, ago(31));
        }
        jdbc.update("insert into anonymous_tally (day, metric, item, value, count) values (?, 'QUIZ', 'Q1', 'RIGHT', 4)",
                Date.valueOf(TODAY.minusDays(31)));
        jdbc.update("insert into anonymous_tally (day, metric, item, value, count) values (?, 'QUIZ', 'Q1', 'RIGHT', 2)",
                Date.valueOf(TODAY.minusDays(29)));
        jdbc.update("insert into prediction (visitor_hash, scene_key, choice) values (?, 'A3:ATTACK', 'ALLOW')",
                RECENT_VISITOR);
        run("r-old", OLD_VISITOR);
        run("r-recent", RECENT_VISITOR);
        for (String[] lab : new String[][]{{"r-old", OLD_VISITOR}, {"r-recent", RECENT_VISITOR}}) {
            jdbc.update("insert into visitor_prediction (run_id, visitor_hash, call, predicted_at) "
                    + "values (?, ?, 'ATTACK', ?)", lab[0], lab[1], ago(31));
            jdbc.update("insert into visitor_assessment (run_id, step_no, visitor_hash, verdict) "
                    + "values (?, 1, ?, 'UNSOUND')", lab[0], lab[1]);
        }
        for (int[] call : new int[][]{{1, 91}, {2, 89}}) {
            jdbc.update("insert into run_model_exchange (request_id, call_no, run_id, step_no, success, captured_at) "
                    + "values (?, ?, 'r-recent', 1, true, ?)", UUID.randomUUID(), call[0], ago(call[1]));
        }
        // X: an old version superseded by a newer one (deleted after 90 days); the newer one stays.
        combination("X", CombinationCatalog.VERSION, "1", 100, OLD_VISITOR);
        combination("X", CombinationCatalog.VERSION, "2", 50, null);
        // Y: old but still the only version (stays). Z: a former catalog version (deleted). W: superseded too
        // recently (stays).
        combination("Y", CombinationCatalog.VERSION, "1", 100, null);
        combination("Z", CombinationCatalog.VERSION - 1, "1", 100, null);
        combination("W", CombinationCatalog.VERSION, "1", 10, null);
        combination("W", CombinationCatalog.VERSION, "2", 5, null);
        for (int days : new int[]{8, 7, 0}) {
            jdbc.update("insert into live_quota (day, subject_kind, subject_hash, used) values (?, 'VISITOR', ?, 1)",
                    Date.valueOf(TODAY.minusDays(days)), RECENT_VISITOR);
        }
        for (int days : new int[]{91, 90}) {
            jdbc.update("insert into live_allotment_alert (day, alerted_at) values (?, ?)",
                    Date.valueOf(TODAY.minusDays(days)), ago(days));
        }
        share("OLDSHAREK1", 91);
        share("RECENTKEY2", 10);
        jdbc.update("insert into retention_log (run_at, deleted) values (?, '{}'::jsonb)", ago(401));
        jdbc.update("insert into retention_log (run_at, deleted) values (?, '{}'::jsonb)", ago(10));
        evidence();
    }

    /** Runs, recordings, the usage ledger and templates around the 13-month and 90-day periods. */
    private void evidence() {
        template("tpl-ready", "READY", null, 500);
        template("tpl-retired-old", "RETIRED", 91, 500);
        template("tpl-retired-new", "RETIRED", 89, 500);
        template("tpl-retired-used", "RETIRED", 91, 500);
        template("tpl-failed-old", "FAILED", null, 91);
        oldRun("ev-old", 397, null);
        oldRun("ev-shown", 397, null);
        oldRun("ev-cell", 397, null);
        oldRun("ev-recent", 395, "tpl-retired-used");
        jdbc.update("""
                insert into execution_spec (spec_id, spec_hash, code_commit, engine_version, effective_mode,
                    endpoint_protection, chat_model, embedding_model, embedding_dimensions, prompt_hash, rule_version,
                    time_zone) values (gen_random_uuid(), ?, 'c', 'e', 'ENFORCE', '{}'::jsonb, 'm', 'em', 1024, ?, ?,
                    'UTC')""", "s".repeat(64), "p".repeat(64), "r".repeat(64));
        recording("rec-published", "PUBLISHED", 100, null, "ev-shown");
        recording("rec-retired-old", "RETIRED", 200, 91, "ev-shown");
        recording("rec-retired-new", "RETIRED", 200, 89, "ev-shown");
        recording("rec-draft-old", "DRAFT", 91, null, "ev-shown");
        recording("rec-draft-new", "DRAFT", 89, null, "ev-shown");
        jdbc.update("""
                insert into combination_record (combo_key, catalog_version, version_key, run_id, recorded_at)
                values ('V', ?, ?, 'ev-cell', ?)""", CombinationCatalog.VERSION, "v".repeat(64), ago(397));
        cost("old", 397);
        cost("recent", 395);
    }

    private void template(String templateId, String status, Integer retiredDaysAgo, int createdDaysAgo) {
        jdbc.update("""
                insert into engine_template (template_id, employee_key, company_seed, company_anchor, company_sha256,
                    status, attempt, created_at, ready_at, retired_at)
                values (?, 'adm-a', 1, ?, ?, ?, 1, ?, ?, ?)""",
                templateId, Date.valueOf(TODAY), "c".repeat(64), status, ago(createdDaysAgo),
                "FAILED".equals(status) ? null : ago(createdDaysAgo),
                retiredDaysAgo == null ? null : ago(retiredDaysAgo));
    }

    private void oldRun(String runId, int daysAgo, String templateId) {
        jdbc.update("""
                insert into run (run_id, scenario_key, scenario_version, employee_key, principal, template_id,
                    organization_id, tenant_id, client_ip, device, company_time, status, started_at, finished_at)
                values (?, 'A3', 1, 'adm-a', ?, ?, 'org', 'tenant', '10.40.12.77', 'test', ?, 'COMPLETED', ?, ?)""",
                runId, "v" + runId, templateId, ago(daysAgo), ago(daysAgo), ago(daysAgo));
    }

    private void recording(String recordId, String status, int recordedDaysAgo, Integer retiredDaysAgo,
                           String runId) {
        jdbc.update("""
                insert into replay_record (record_id, pair_key, scene, scenario_key, scenario_version, spec_hash,
                    repetitions, agreeing, representative_run_id, outcome_signature, status, recorded_at, retired_at)
                values (?, ?, 'ATTACK', 'A3', 1, ?, 5, 5, ?, 'sig', ?, ?, ?)""",
                recordId, recordId.substring(4, 7), "s".repeat(64), runId, status, ago(recordedDaysAgo),
                retiredDaysAgo == null ? null : ago(retiredDaysAgo));
    }

    private void cost(String model, int daysAgo) {
        jdbc.update("""
                insert into cost_ledger (entry_id, run_id, kind, model, prompt_tokens, completion_tokens, total_tokens,
                    recorded_at) values (gen_random_uuid(), 'ev-old', 'CHAT', ?, 1, 1, 2, ?)""", model, ago(daysAgo));
    }

    private void run(String runId, String visitor) {
        jdbc.update("""
                insert into run (run_id, scenario_key, scenario_version, employee_key, principal, organization_id,
                    tenant_id, client_ip, device, company_time, status, live_visitor_hash, live_run)
                values (?, 'K2', 1, 'adm-a', ?, 'org', 'tenant', '10.40.12.77', 'test', ?, 'COMPLETED', ?, true)""",
                runId, "v" + runId, ago(31), visitor);
    }

    private void combination(String combo, int catalog, String version, int daysAgo, String visitor) {
        jdbc.update("""
                insert into combination_record (combo_key, catalog_version, version_key, run_id, visitor_hash,
                    recorded_at) values (?, ?, ?, 'r-recent', ?, ?)""",
                combo, catalog, version.repeat(64), visitor, ago(daysAgo));
    }

    private void share(String key, int daysAgo) {
        jdbc.update("""
                insert into share_card (share_key, pair_key, language, my_hits, my_total, contexa_hits, contexa_total,
                    host, image, created_at, last_shared_at)
                values (?, 'A3', 'ko', 1, 2, ?, 2, 'demo.example', ?, ?, ?)""",
                key, daysAgo == 91 ? 1 : 2, new byte[]{1}, ago(daysAgo), ago(daysAgo));
    }

    private static Timestamp ago(int days) {
        return Timestamp.from(NOW.minus(Duration.ofDays(days)));
    }

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
