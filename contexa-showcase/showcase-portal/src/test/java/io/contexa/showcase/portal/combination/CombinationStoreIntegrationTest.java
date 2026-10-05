package io.contexa.showcase.portal.combination;

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
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plan section 2 on unresolved decisions (docs/showcase/계획대조-검수.md N-2): a cell record whose run got no engine
 * decision is neither shown nor reused, the next run of the cell takes its place, and a resolved record is never
 * replaced. Skipped without Docker.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest
class CombinationStoreIntegrationTest {

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

    private static final String VERSION = "v".repeat(64);

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("showcase.internal.signing-key", CombinationStoreIntegrationTest::randomKey);
    }

    @Autowired
    JdbcTemplate jdbc;

    @Test
    void anUnresolvedRecordIsHiddenAndReplacedWhileAResolvedOneStays() {
        jdbc.update("delete from combination_record");
        CombinationStore store = new CombinationStore(new NamedParameterJdbcTemplate(jdbc));
        run("run-unresolved", true);
        run("run-next", false);
        run("run-later", false);

        assertThat(store.save("A", VERSION, "run-unresolved", null)).isTrue();
        assertThat(store.unresolved("run-unresolved")).isTrue();
        assertThat(store.find("A", VERSION)).as("a technical failure is not a cell result").isEmpty();
        assertThat(store.forVersions(List.of(VERSION))).isEmpty();

        assertThat(store.save("A", VERSION, "run-next", "h".repeat(64))).as("the next run takes its place").isTrue();
        assertThat(store.find("A", VERSION)).map(CombinationStore.RecordRow::runId).contains("run-next");

        assertThat(store.save("A", VERSION, "run-later", null)).as("a resolved record is kept").isFalse();
        assertThat(store.find("A", VERSION)).map(CombinationStore.RecordRow::runId).contains("run-next");
        assertThat(store.forVersions(List.of(VERSION))).extracting(CombinationStore.RecordRow::runId)
                .containsExactly("run-next");
    }

    private void run(String runId, boolean unresolved) {
        jdbc.update("""
                insert into run (run_id, scenario_key, scenario_version, employee_key, principal, organization_id,
                    tenant_id, client_ip, device, company_time, status)
                values (?, 'A', 1, 'adm-a', ?, 'org', 'tenant', '10.40.12.77', 'test', now(), 'COMPLETED')""",
                runId, "v-" + runId);
        jdbc.update("""
                insert into run_decision (request_id, run_id, step_no, final_action, applied, unresolved, records,
                    events) values (?, ?, 1, ?, 'BEFORE_RESPONSE', ?, '[]'::jsonb, '[]'::jsonb)""",
                UUID.randomUUID(), runId, unresolved ? "CHALLENGE" : "ALLOW", unresolved);
    }

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
