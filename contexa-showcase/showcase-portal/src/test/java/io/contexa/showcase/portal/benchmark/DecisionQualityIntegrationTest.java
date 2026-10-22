package io.contexa.showcase.portal.benchmark;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * BM-S8 of docs/showcase/벤치마크-구현계획.md on a real database: the decision quality (G5 of the v21 plan) is published
 * for a measurement setting only from a finished protocol that ran that setting, a republication replaces the row, and
 * visitors see the stored view of the setting they name only once it is published (404 before).
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest
@AutoConfigureMockMvc
class DecisionQualityIntegrationTest {

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

    private static final String SIGNING_KEY = randomKey();

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("showcase.internal.signing-key", () -> SIGNING_KEY);
    }

    @Autowired
    MockMvc mvc;

    @Autowired
    JdbcTemplate jdbc;

    @Autowired
    DecisionQualityPublications publications;

    @Autowired
    ObjectMapper json;

    @Test
    void aProtocolIsPublishedOnlyWhenFinishedAndOfTheSetting() {
        String setting = "a".repeat(64);
        String done = protocol(Instant.parse("2026-10-20T01:00:00Z"));
        run(done, setting);
        String running = protocol(null);
        run(running, setting);
        String other = protocol(Instant.parse("2026-10-20T01:00:00Z"));
        run(other, "b".repeat(64));

        assertThat(publications.refusal(setting, "p-missing")).contains(DecisionQualityPublications.UNKNOWN_PROTOCOL);
        assertThat(publications.refusal(setting, running)).contains(DecisionQualityPublications.PROTOCOL_UNFINISHED);
        assertThat(publications.refusal(setting, other)).contains(DecisionQualityPublications.OTHER_SETTING);
        assertThat(publications.refusal(setting, done)).isEmpty();
    }

    @Test
    void visitorsSeeTheStoredViewOfTheNamedSettingOnlyOncePublished() throws Exception {
        String setting = "c".repeat(64);
        String done = protocol(Instant.parse("2026-10-20T01:00:00Z"));
        run(done, setting);

        assertThat(status("/api/benchmark/decision-quality?setting=" + setting)).as("before publishing").isEqualTo(404);
        assertThat(status("/api/benchmark/decision-quality?setting=not-a-setting")).isEqualTo(404);

        publications.publish(setting, done, "{\"setting\": \"" + setting + "\", \"reasonMatch\": {\"hits\": 7}}",
                Instant.parse("2026-10-20T01:10:00Z"));
        publications.publish(setting, done, "{\"setting\": \"" + setting + "\", \"reasonMatch\": {\"hits\": 9}}",
                Instant.parse("2026-10-20T01:20:00Z"));

        JsonNode view = view("/api/benchmark/decision-quality?setting=" + setting);
        assertThat(view.path("reasonMatch").path("hits").asInt()).as("the republication replaced the row").isEqualTo(9);
        assertThat(publications.published(setting)).isPresent();
        assertThat(publications.published("d".repeat(64))).isEqualTo(Optional.empty());
    }

    private int status(String path) throws Exception {
        return mvc.perform(get(path)).andReturn().getResponse().getStatus();
    }

    private JsonNode view(String path) throws Exception {
        MockHttpServletResponse response = mvc.perform(get(path)).andReturn().getResponse();
        assertThat(response.getStatus()).as(path).isEqualTo(200);
        return json.readTree(response.getContentAsString());
    }

    private String protocol(Instant finishedAt) {
        String protocolId = "p-" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        jdbc.update("""
                insert into measurement_protocol (protocol_id, repeat, cases, started_at, finished_at)
                values (?, 3, '["A3"]'::jsonb, ?, ?)""", protocolId, Timestamp.from(Instant.parse(
                "2026-10-20T00:00:00Z")), finishedAt == null ? null : Timestamp.from(finishedAt));
        return protocolId;
    }

    private void run(String protocol, String setting) {
        String runId = "run-" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        jdbc.update("""
                insert into run (run_id, scenario_key, scenario_version, employee_key, principal, organization_id,
                    tenant_id, client_ip, device, company_time, status, protocol_id, setting_hash)
                values (?, 'A3', 1, 'adm-a', ?, 'org', 'tenant', '10.40.12.77', 'test', now(), 'COMPLETED', ?, ?)""",
                runId, "v" + runId, protocol, setting);
    }

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
