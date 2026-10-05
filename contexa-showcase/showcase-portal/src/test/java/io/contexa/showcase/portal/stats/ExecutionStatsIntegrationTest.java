package io.contexa.showcase.portal.stats;

import io.contexa.showcase.portal.replay.PairCatalog;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.stats.ExecutionStats.Result;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * P5-BE-01: every number of the execution statistics equals the count of the stored runs it comes from. The rows
 * below are a small world whose expected numbers are worked out by hand in the comments.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest
class ExecutionStatsIntegrationTest {

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

    private static final String SIGNING_KEY = randomKey();
    private static final String SPEC = "a".repeat(64);
    private static final Instant NOW = Instant.parse("2026-10-05T12:00:00Z");

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
    ScenarioCatalog scenarios;

    @Autowired
    PairCatalog pairs;

    @Test
    void everyNumberEqualsTheStoredRuns() {
        world();
        MovingClock clock = new MovingClock(NOW);
        ExecutionStats stats = new ExecutionStats(new NamedParameterJdbcTemplate(jdbc), scenarios, pairs, clock);

        StatsView view = stats.view();

        // Completed: t1, t2, t3, n1 and the grid cell; the forced run is left out, the failed run counted apart.
        assertThat(view.runs()).isEqualTo(new StatsView.Runs(5, 1, 4, 1, NOW.minusSeconds(3600 * 30),
                NOW.minusSeconds(60)));
        // Resolved decisions 1000, 2000, 3000 and 4000 ms (t3's unresolved and the forced run left out).
        assertThat(view.decisionTime()).isEqualTo(new StatsView.DecisionTime(4, 2500L, 3850L));
        assertThat(view.engineActions()).isEqualTo(Map.of("ALLOW", 2L, "CHALLENGE", 1L, "BLOCK", 1L, "ESCALATE", 0L));
        assertThat(view.unresolved()).isEqualTo(new StatsView.Unresolved(1, 1));
        assertThat(view.agreement().agreeing()).isEqualTo(9);
        assertThat(view.agreement().repetitions()).isEqualTo(10);
        assertThat(view.agreement().recordings()).extracting(StatsView.Recording::scene)
                .containsExactly("ATTACK", "LEGITIMATE");
        assertThat(view.scope()).isEqualTo(new StatsView.Scope(3, 1, 1));
        // A3 and A1 are threats (A1 decides at its featured step 1, not at its last step), A3T is normal work.
        assertThat(view.layers()).containsExactly(
                new StatsView.LayerStats("A", new StatsView.Threat(3, 2, 1, 0), new StatsView.Normal(1, 1, 0, 0, 0)),
                new StatsView.LayerStats("B", new StatsView.Threat(3, 3, 0, 0), new StatsView.Normal(1, 1, 0, 0, 0)),
                new StatsView.LayerStats("C1", new StatsView.Threat(3, 1, 2, 0), new StatsView.Normal(1, 0, 0, 1, 0)),
                new StatsView.LayerStats("C2", new StatsView.Threat(3, 0, 2, 1), new StatsView.Normal(1, 1, 0, 0, 0)),
                new StatsView.LayerStats("D", new StatsView.Threat(3, 2, 1, 0), new StatsView.Normal(1, 0, 1, 0, 0)));
        assertThat(view.spec().specHash()).isEqualTo(SPEC);
        assertThat(view.spec().chatModel()).isEqualTo("gpt-5-nano");
        assertThat(view.specCount()).isEqualTo(1);

        run("t4", "A3", "COMPLETED", null, null, NOW.minusSeconds(30));
        assertThat(stats.view()).as("cached for a minute").isSameAs(view);
        clock.advance(Duration.ofMinutes(1));
        assertThat(stats.view().runs().completed()).isEqualTo(6);
    }

    @Test
    void controlDsChecksAndHoldsAreReadAsScreenOneShowsThem() {
        assertThat(ExecutionStats.result("D", "REFUSED", 401, false)).isEqualTo(Result.CHALLENGED);
        assertThat(ExecutionStats.result("D", "REFUSED", 423, false)).isEqualTo(Result.HELD_FOR_REVIEW);
        assertThat(ExecutionStats.result("D", "REFUSED", 401, true)).isEqualTo(Result.UNRESOLVED);
        assertThat(ExecutionStats.result("D", "DELIVERED", 200, true)).as("the data left all the same")
                .isEqualTo(Result.DELIVERED);
        assertThat(ExecutionStats.result("D", "CUT", 200, false)).isEqualTo(Result.STOPPED);
        assertThat(ExecutionStats.result("C1", "REFUSED", 401, false)).isEqualTo(Result.STOPPED);
        assertThat(ExecutionStats.result("A", "ERROR", null, false)).isEqualTo(Result.UNRESOLVED);
    }

    private void world() {
        jdbc.update("""
                insert into execution_spec (spec_id, spec_hash, code_commit, engine_version, effective_mode,
                    endpoint_protection, chat_model, embedding_model, embedding_dimensions, prompt_hash, rule_version,
                    time_zone)
                values (?, ?, 'abc123', '0.1.0', 'ENFORCE', '{}'::jsonb, 'gpt-5-nano', 'text-embedding-3-small', 1024,
                    ?, ?, 'UTC')""", UUID.randomUUID(), SPEC, "b".repeat(64), "c".repeat(64));
        // t1 (A3, threat): the rule controls in front let it through, C1 and C2 stop it, D allows (1000 ms).
        run("t1", "A3", "COMPLETED", null, null, NOW.minusSeconds(3600 * 30));
        arms("t1", 1, "DELIVERED", "DELIVERED", "REFUSED", "REFUSED", "DELIVERED", 200);
        decision("t1", 1, "ALLOW", false, "NEXT_REQUEST", 1000L);
        // t2 (A3, threat): D blocks before the response (3000 ms).
        run("t2", "A3", "COMPLETED", null, null, NOW.minusSeconds(600));
        arms("t2", 1, "DELIVERED", "DELIVERED", "REFUSED", "ERROR", "REFUSED", 403);
        decision("t2", 1, "BLOCK", false, "BEFORE_RESPONSE", 3000L);
        // t3 (A1, threat, featured step 1): the WAF stops step 1; D delivers step 1 with an unresolved decision and
        // has no new analysis at step 2, where it refuses (step 2 is not the decisive step).
        run("t3", "A1", "COMPLETED", null, null, NOW.minusSeconds(300));
        arms("t3", 1, "REFUSED", "DELIVERED", "DELIVERED", "REFUSED", "DELIVERED", 200);
        arms("t3", 2, "REFUSED", "DELIVERED", "DELIVERED", "REFUSED", "REFUSED", 403);
        decision("t3", 1, "CHALLENGE", true, "NEXT_REQUEST", 9000L);
        decision("t3", 2, null, false, "NONE", null);
        // n1 (A3T, normal, a visitor's live run): C1's volume threshold stops it, D asks for an extra check (2000 ms).
        run("n1", "A3T", "COMPLETED", null, "f".repeat(64), NOW.minusSeconds(120));
        arms("n1", 1, "DELIVERED", "DELIVERED", "REFUSED", "DELIVERED", "REFUSED", 401);
        decision("n1", 1, "CHALLENGE", false, "BEFORE_RESPONSE", 2000L);
        // A condition grid cell (no ground truth): counted as a run and a decision (4000 ms), not as a miss.
        run("g1", "adm-a.DAWN.40.NONE.USUAL", "COMPLETED", null, null, NOW.minusSeconds(60));
        arms("g1", 1, "DELIVERED", "DELIVERED", "DELIVERED", "DELIVERED", "DELIVERED", 200);
        decision("g1", 1, "ALLOW", false, "NEXT_REQUEST", 4000L);
        // Left out: a run with a forced decision, and a failed run.
        run("f1", "A3", "COMPLETED", "CHALLENGE", null, NOW.minusSeconds(30));
        arms("f1", 1, "DELIVERED", "DELIVERED", "DELIVERED", "DELIVERED", "REFUSED", 401);
        decision("f1", 1, "CHALLENGE", false, "BEFORE_RESPONSE", 50L);
        run("x1", "A3", "FAILED", null, null, NOW.minusSeconds(30));
        // Published recordings 4 of 5 and 5 of 5; a draft is left out.
        record("r1", "ATTACK", "PUBLISHED", 4, 5, "t1");
        record("r2", "LEGITIMATE", "PUBLISHED", 5, 5, "n1");
        record("r3", "ATTACK", "DRAFT", 1, 5, "t2");
    }

    private void run(String runId, String scenario, String status, String forced, String liveVisitor,
                     Instant startedAt) {
        jdbc.update("""
                insert into run (run_id, scenario_key, scenario_version, employee_key, principal, organization_id,
                    tenant_id, client_ip, device, company_time, status, spec_hash, started_at, forced_action,
                    live_visitor_hash, live_run)
                values (?, ?, 1, 'adm-a', ?, 'org', 'tenant', '10.40.12.77', 'test', ?, ?, ?, ?, ?, ?, ?)""",
                runId, scenario, "v" + runId, Timestamp.from(startedAt), status, SPEC, Timestamp.from(startedAt),
                forced, liveVisitor, liveVisitor != null);
    }

    private void arms(String runId, int step, String a, String b, String c1, String c2, String d, int dStatus) {
        String[][] arms = {{"A", a}, {"B", b}, {"C1", c1}, {"C2", c2}, {"D", d}};
        for (String[] arm : arms) {
            Integer status = "D".equals(arm[0]) ? Integer.valueOf(dStatus)
                    : "DELIVERED".equals(arm[1]) ? Integer.valueOf(200) : "ERROR".equals(arm[1]) ? null : 403;
            jdbc.update("""
                    insert into run_arm_result (run_id, step_no, control, request_id, operation, method, path,
                        company_time, http_status, outcome, sent_at)
                    values (?, ?, ?, ?, 'EXPORT', 'POST', '/api/x', ?, ?, ?, ?)""",
                    runId, step, arm[0], UUID.randomUUID(), Timestamp.from(NOW), status, arm[1], Timestamp.from(NOW));
        }
    }

    private void decision(String runId, int step, String action, boolean unresolved, String applied, Long totalMs) {
        jdbc.update("""
                insert into run_decision (request_id, run_id, step_no, final_action, unresolved, applied,
                    total_analysis_ms, records, events)
                values (?, ?, ?, ?, ?, ?, ?, '[]'::jsonb, '[]'::jsonb)""",
                UUID.randomUUID(), runId, step, action, unresolved, applied, totalMs);
    }

    private void record(String recordId, String scene, String status, int agreeing, int repetitions, String runId) {
        jdbc.update("""
                insert into replay_record (record_id, pair_key, scene, scenario_key, scenario_version, spec_hash,
                    repetitions, agreeing, representative_run_id, outcome_signature, status)
                values (?, 'A3', ?, 'A3', 1, ?, ?, ?, ?, 'sig', ?)""",
                recordId, scene, SPEC, repetitions, agreeing, runId, status);
    }

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    private static final class MovingClock extends Clock {
        private Instant now;

        MovingClock(Instant now) {
            this.now = now;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
