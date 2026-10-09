package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
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
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W1-0d (docs/showcase/데모-재설계.md, found on the real server 2026-10-06): an approved release has no failure reason
 * and is stored with the whole trace instead of failing the run, and a long failure reason is stored cut to the column.
 * Skipped without Docker.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest
class RunReleaseStoreIntegrationTest {

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

    private static final Instant BLOCKED = Instant.parse("2026-10-06T14:23:10Z");

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("showcase.internal.signing-key", RunReleaseStoreIntegrationTest::randomKey);
    }

    @Autowired
    JdbcTemplate jdbc;

    @Autowired
    ObjectMapper json;

    private RunStore store;

    @BeforeEach
    void storeOnTheTestDatabase() {
        store = new RunStore(new NamedParameterJdbcTemplate(jdbc), json);
    }

    @Test
    void anApprovedReleaseIsStoredWithoutAFailureReason() {
        run("run-released");
        ControlSession.StepOutcome reissue = new ControlSession.StepOutcome(UUID.randomUUID().toString(), "GET",
                "/api/projects/GB-500/exports/stream", BLOCKED, 200, "DELIVERED", 4831, null, null, null, 37155L,
                BLOCKED.plusSeconds(11), null);
        Approver.BlockRecord block = new Approver.BlockRecord(4, "adm-a-run", "UNBLOCK_REQUESTED", "forced", "2026-10-06T14:23:10",
                "approved migration", true, "2026-10-06T14:23:15");
        store.release("run-released", 1, UUID.randomUUID().toString(), new ControlSession.ReleaseTrace(true, null,
                BLOCKED, BLOCKED.plusSeconds(1), BLOCKED.plusSeconds(3), BLOCKED.plusSeconds(5),
                BLOCKED.plusSeconds(7), block, reissue));

        Map<String, Object> row = jdbc.queryForMap("select released, reason, reissue_outcome, reissue_delivered, "
                + "block_record ->> 'status' as block_status, block_record ->> 'username' as block_username "
                + "from run_release where run_id = 'run-released'");
        assertThat(row).containsEntry("released", true).containsEntry("reason", null)
                .containsEntry("reissue_outcome", "DELIVERED").containsEntry("reissue_delivered", 4831)
                .containsEntry("block_status", "UNBLOCK_REQUESTED").containsEntry("block_username", "adm-a-run");
    }

    @Test
    void aLongFailureReasonIsStoredCutToTheColumn() {
        run("run-refused");
        String reason = "IOException: " + "x".repeat(400);
        store.release("run-refused", 1, null, new ControlSession.ReleaseTrace(false, reason, BLOCKED, null, null,
                null, null, null, null));

        assertThat(jdbc.queryForObject("select reason from run_release where run_id = 'run-refused'", String.class))
                .isEqualTo(reason.substring(0, 200));
    }

    private void run(String runId) {
        jdbc.update("delete from run where run_id = ?", runId);
        jdbc.update("""
                insert into run (run_id, scenario_key, scenario_version, employee_key, principal, organization_id,
                                 tenant_id, client_ip, device, company_time, status, started_at)
                values (?, 'A3ST', 1, 'adm-a', 'v-test', 'org', 'tenant', '10.40.12.77', 'test', now(), 'RUNNING',
                        now())""", runId);
    }

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
