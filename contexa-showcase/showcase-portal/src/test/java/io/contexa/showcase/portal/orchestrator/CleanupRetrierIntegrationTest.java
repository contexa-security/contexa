package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

import java.io.IOException;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plan section 8 (docs/showcase/계획대조-검수.md N-6): a finished run whose clean-up failed is cleaned again, a run
 * left RUNNING by a stopped portal is cleaned and closed, a run in progress and a clean run are left alone, and a
 * clean-up that keeps failing stops after the retry limit. Skipped without Docker.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest
class CleanupRetrierIntegrationTest {

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Instant NOW = Instant.parse("2026-10-05T12:00:00Z");

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("showcase.internal.signing-key", CleanupRetrierIntegrationTest::randomKey);
    }

    @Autowired
    JdbcTemplate jdbc;

    private final List<String> cleaned = new CopyOnWriteArrayList<>();
    private final AtomicBoolean engineDown = new AtomicBoolean(false);

    /**
     * 벤치마크 계획 BM-S9: a protocol's job lives in the portal, so a protocol a stopped portal left unfinished gets no
     * more runs; the start closes it at its last run (at its start when none ran) and keeps a finished one.
     */
    @Test
    void aProtocolAStoppedPortalLeftUnfinishedEndsAtItsLastRun() throws Exception {
        jdbc.update("delete from run");
        jdbc.update("delete from measurement_protocol");
        protocol("p-stopped", Duration.ofHours(3), null);
        protocol("p-empty", Duration.ofHours(2), null);
        protocol("p-done", Duration.ofHours(5), Duration.ofHours(4));
        run("run-first", "COMPLETED", Duration.ofMinutes(170), null);
        run("run-last", "COMPLETED", Duration.ofMinutes(100), null);
        jdbc.update("""
                update run set protocol_id = 'p-stopped', finished_at = started_at + interval '5 minutes'
                 where run_id in ('run-first', 'run-last')""");

        new OrchestrationConfiguration()
                .unfinishedProtocolCloser(new RunStore(new NamedParameterJdbcTemplate(jdbc), JSON)).run(null);

        assertThat(finished("p-stopped")).isEqualTo(NOW.minus(Duration.ofMinutes(95)));
        assertThat(finished("p-empty")).isEqualTo(NOW.minus(Duration.ofHours(2)));
        assertThat(finished("p-done")).isEqualTo(NOW.minus(Duration.ofHours(4)));
    }

    @Test
    void failedAndAbandonedRunsAreCleanedAgainAndTheRestIsLeftAlone() {
        jdbc.update("delete from run");
        run("run-failed", "COMPLETED", Duration.ofMinutes(10), "{\"engineError\":\"timeout\",\"business\":{}}");
        run("run-abandoned", "RUNNING", Duration.ofHours(2), null);
        run("run-going", "RUNNING", Duration.ofMinutes(5), null);
        run("run-clean", "COMPLETED", Duration.ofMinutes(10), "{\"engine\":{},\"business\":{}}");

        CleanupRetrier.Pass pass = retrier().run();

        assertThat(pass).isEqualTo(new CleanupRetrier.Pass(2, 2, 0));
        assertThat(cleaned).containsExactlyInAnyOrder("engine run-failed", "engine run-abandoned",
                "business run-abandoned");
        assertThat(cleanup("run-failed")).doesNotContain("engineError").contains("\"retries\": 1");
        assertThat(jdbc.queryForObject("select status || ' ' || failure from run where run_id = 'run-abandoned'",
                String.class)).isEqualTo("FAILED " + CleanupRetrier.ABANDONED);
        assertThat(jdbc.queryForObject("select status from run where run_id = 'run-going'", String.class))
                .isEqualTo("RUNNING");
        assertThat(retrier().run().tried()).as("nothing is left to clean").isZero();
    }

    @Test
    void aCleanUpThatKeepsFailingStopsAfterTheRetryLimit() {
        jdbc.update("delete from run");
        engineDown.set(true);
        run("run-stuck", "COMPLETED", Duration.ofMinutes(10), "{\"engineError\":\"timeout\"}");

        for (int pass = 1; pass <= CleanupRetrier.MAX_RETRIES; pass++) {
            assertThat(retrier().run()).isEqualTo(new CleanupRetrier.Pass(1, 0, 1));
        }

        assertThat(retrier().run().tried()).isZero();
        assertThat(cleanup("run-stuck")).contains("engineError").contains("\"retries\": 5");
    }

    private CleanupRetrier retrier() {
        WorkloadAdmin admin = new WorkloadAdmin(null, null, JSON) {
            @Override
            public JsonNode deleteEnginePrincipal(String runId, String username) throws IOException {
                if (engineDown.get()) {
                    throw new IOException("control D is not reachable");
                }
                cleaned.add("engine " + runId);
                return JSON.createObjectNode();
            }

            @Override
            public JsonNode deletePlainRun(String runId) {
                cleaned.add("business " + runId);
                return JSON.createObjectNode();
            }
        };
        return new CleanupRetrier(new RunStore(new NamedParameterJdbcTemplate(jdbc), JSON), admin, JSON,
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private void protocol(String protocolId, Duration startedAgo, Duration finishedAgo) {
        jdbc.update("""
                insert into measurement_protocol (protocol_id, repeat, cases, started_at, finished_at)
                values (?, 5, cast('["K2"]' as jsonb), ?, ?)""",
                protocolId, Timestamp.from(NOW.minus(startedAgo)),
                finishedAgo == null ? null : Timestamp.from(NOW.minus(finishedAgo)));
    }

    private Instant finished(String protocolId) {
        return jdbc.queryForObject("select finished_at from measurement_protocol where protocol_id = ?",
                Timestamp.class, protocolId).toInstant();
    }

    private void run(String runId, String status, Duration startedAgo, String cleanup) {
        jdbc.update("""
                insert into run (run_id, scenario_key, scenario_version, employee_key, principal, organization_id,
                    tenant_id, client_ip, device, company_time, status, started_at, cleanup)
                values (?, 'K2', 1, 'eng-k', ?, 'org', 'tenant', '10.40.12.77', 'test', ?, ?, ?,
                    cast(? as jsonb))""",
                runId, "v-" + runId, Timestamp.from(NOW), status, Timestamp.from(NOW.minus(startedAgo)), cleanup);
    }

    private String cleanup(String runId) {
        return jdbc.queryForObject("select cleanup::text from run where run_id = ?", String.class, runId);
    }

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
