package io.contexa.showcase.portal.reactivity;

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
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * W7-13 on a real database: the prompt quality is published for a measurement setting only from a finished protocol
 * and a batch of that setting, and visitors see the stored view only once it is published (404 before).
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest
@AutoConfigureMockMvc
class PromptQualityIntegrationTest {

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
    PromptQualityPublications publications;

    @Autowired
    ObjectMapper json;

    @Test
    void aBatchAndAProtocolArePublishedOnlyWhenFinishedAndOfTheSetting() {
        String setting = "a".repeat(64);
        String other = "b".repeat(64);
        String done = protocol(Instant.parse("2026-10-16T04:00:00Z"));
        String running = protocol(null);
        run("COMPLETED", done, setting);
        batch("w7-a", run("COMPLETED", null, setting), Instant.parse("2026-10-16T05:00:00Z"));
        batch("w7-a", run("FAILED", null, null), Instant.parse("2026-10-16T04:30:00Z"));
        batch("w7-mixed", run("COMPLETED", null, setting), Instant.parse("2026-10-16T05:00:00Z"));
        batch("w7-mixed", run("COMPLETED", null, other), Instant.parse("2026-10-16T05:10:00Z"));

        assertThat(publications.refusal(setting, "w7-a", "p-unknown")).contains("UNKNOWN_PROTOCOL");
        assertThat(publications.refusal(setting, "w7-a", running)).contains("PROTOCOL_UNFINISHED");
        assertThat(publications.refusal(other, "w7-a", done)).contains("PROTOCOL_NOT_IN_SETTING");
        assertThat(publications.refusal(setting, "w7-none", done)).contains("UNKNOWN_BATCH");
        assertThat(publications.refusal(setting, "w7-mixed", done)).as("a run of another setting")
                .contains("BATCH_NOT_IN_SETTING");
        assertThat(publications.refusal(setting, "w7-a", done)).as("a failed run does not move the batch")
                .isEmpty();
        assertThat(publications.measuredAt("w7-a", done)).isEqualTo(Instant.parse("2026-10-16T05:00:00Z"));
    }

    @Test
    void visitorsSeeTheStoredViewOnlyOncePublished() throws Exception {
        String first = "c".repeat(64);
        String second = "d".repeat(64);
        String done = protocol(Instant.parse("2026-10-16T04:00:00Z"));
        assertThat(status("/api/benchmark/prompt-quality?setting=" + first)).as("before publishing").isEqualTo(404);

        publications.publish(first, "w7-b", done, "{\"setting\": \"" + first + "\", \"delivery\": {\"hits\": 10}}",
                Instant.parse("2030-01-01T00:00:00Z"));
        publications.publish(second, "w7-c", done, "{\"setting\": \"" + second + "\", \"delivery\": {\"hits\": 7}}",
                Instant.parse("2030-01-02T00:00:00Z"));

        assertThat(view("/api/benchmark/prompt-quality?setting=" + first).path("delivery").path("hits").asInt())
                .isEqualTo(10);
        assertThat(view("/api/benchmark/prompt-quality").path("setting").asText()).as("the latest published")
                .isEqualTo(second);
        assertThat(status("/api/benchmark/prompt-quality?setting=" + "e".repeat(64))).isEqualTo(404);
        assertThat(status("/api/benchmark/prompt-quality?setting=not-a-setting")).isEqualTo(404);
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
                "2026-10-16T01:00:00Z")), finishedAt == null ? null : Timestamp.from(finishedAt));
        return protocolId;
    }

    private String run(String status, String protocol, String setting) {
        String runId = "run-" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        jdbc.update("""
                insert into run (run_id, scenario_key, scenario_version, employee_key, principal, organization_id,
                    tenant_id, client_ip, device, company_time, status, protocol_id, setting_hash)
                values (?, 'A3', 1, 'adm-a', ?, 'org', 'tenant', '10.40.12.77', 'test', now(), ?, ?, ?)""",
                runId, "v" + runId, status, protocol, setting);
        return runId;
    }

    private void batch(String batch, String runId, Instant recordedAt) {
        jdbc.update("""
                insert into reactivity_run (run_id, batch_id, kind, label, case_key, recorded_at)
                values (?, ?, 'LAB', 'A3:approval=true', 'A3', ?)""", runId, batch, Timestamp.from(recordedAt));
    }

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
