package io.contexa.showcase.portal.lab;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.visitor.VisitorCookies;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
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
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * V-7: only the visitor who started a run assesses its decision, once per step; the lab's records are kept with the run
 * and read back only by their own visitor (docs/showcase/데모-재설계.md 5A.1, W2-2, W2-3).
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(properties = {
        "showcase.portal.controls.a=http://127.0.0.1:9/", "showcase.portal.controls.b=http://127.0.0.1:9/",
        "showcase.portal.controls.c1=http://127.0.0.1:9/", "showcase.portal.controls.c2=http://127.0.0.1:9/",
        "showcase.portal.controls.d=http://127.0.0.1:9/", "showcase.live.enabled=true"})
@AutoConfigureMockMvc
class LabIntegrationTest {

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
    LabStore store;

    @Autowired
    LabComposer composer;

    @Autowired
    ScenarioCatalog catalog;

    @Autowired
    ObjectMapper json;

    @Test
    void onlyTheRunsOwnVisitorAssessesItsDecisionAndOnlyOnce() throws Exception {
        Cookie owner = visitor();
        Cookie other = visitor();
        String runId = "run-" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        run(runId, hash(owner));

        assertThat(assess(other, runId, 1, "UNSOUND").getStatus()).as("someone else's run").isEqualTo(403);
        assertThat(assess(owner, runId, 1, "UNSOUND").getStatus()).isEqualTo(201);
        assertThat(assess(owner, runId, 1, "SOUND").getStatus()).as("once per step").isEqualTo(409);
        assertThat(assess(owner, runId, 2, "SOUND").getStatus()).as("a step without a decision").isEqualTo(404);
        assertThat(assess(owner, runId, 1, "MAYBE").getStatus()).isEqualTo(400);
        assertThat(jdbc.queryForObject("select verdict || ' ' || reasons::text from visitor_assessment "
                + "where run_id = ?", String.class, runId)).isEqualTo("UNSOUND [\"MISSED_SIGNAL\", \"DISAGREE_TRUTH\"]");
    }

    @Test
    void aLabRunsCompositionAndCallAreReadBackByItsOwnVisitorOnly() throws Exception {
        Cookie owner = visitor();
        Cookie other = visitor();
        String runId = "run-" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        run(runId, hash(owner));
        LabComposer.Composed designed = new LabComposer.Composed(catalog.find("A3").orElseThrow(), true,
                List.of(), null);
        Instant called = Instant.parse("2026-10-06T13:00:00Z");
        store.ran(runId, designed, "A3", called.plusSeconds(1), hash(owner),
                new LabStore.Prediction("ATTACK", Map.of("D", "BLOCK", "A", "PASS"), called));

        JsonNode mine = json.readTree(mvc.perform(get("/api/lab/runs/recent").cookie(owner))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertThat(mine).hasSize(1);
        assertThat(mine.get(0).path("runId").asText()).isEqualTo(runId);
        assertThat(mine.get(0).path("call").asText()).isEqualTo("ATTACK");
        assertThat(mine.get(0).path("designed").asBoolean()).isTrue();
        assertThat(mine.get(0).path("approaches").path("D").asText()).isEqualTo("BLOCK");
        assertThat(json.readTree(mvc.perform(get("/api/lab/runs/recent").cookie(other))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString())).isEmpty();
        assertThat(jdbc.queryForObject("select predicted_at from visitor_prediction where run_id = ?",
                Timestamp.class, runId).toInstant()).as("the call is kept with the time it was sent").isEqualTo(called);
    }

    /**
     * 5A.1 ⑤: the other visitors' assessments of the same request: same definition, same setting, same step, older
     * than an hour, completed and unforced runs; the asking visitor's own assessment is left out.
     */
    @Test
    void theSameRequestsOtherAssessmentsAreCountedAfterTheDelay() throws Exception {
        Cookie asking = visitor();
        String sha = "e".repeat(64);
        String setting = "f".repeat(64);
        Instant old = Instant.now().minusSeconds(7200);
        String base = peerRun(hash(asking), sha, setting, null);
        assessed(peerRun("1".repeat(64), sha, setting, null), "1".repeat(64), "SOUND", "[]", old);
        assessed(peerRun("2".repeat(64), sha, setting, null), "2".repeat(64), "UNSOUND", "[\"MISSED_SIGNAL\"]", old);
        assessed(peerRun("3".repeat(64), sha, setting, null), "3".repeat(64), "UNSOUND", "[]",
                Instant.now().minusSeconds(600));
        assessed(peerRun("4".repeat(64), "d".repeat(64), setting, null), "4".repeat(64), "UNSOUND", "[]", old);
        assessed(peerRun("5".repeat(64), sha, setting, "BLOCK"), "5".repeat(64), "UNSOUND", "[]", old);
        assessed(peerRun(hash(asking), sha, setting, null), hash(asking), "UNSOUND", "[]", old);

        JsonNode peers = json.readTree(mvc.perform(get("/api/runs/" + base + "/steps/1/peer-assessments")
                .cookie(asking)).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());

        assertThat(peers.path("assessments").asLong()).as("visitors 1 and 2 only").isEqualTo(2);
        assertThat(peers.path("assessors").asLong()).isEqualTo(2);
        assertThat(peers.path("verdicts").path("SOUND").asLong()).isEqualTo(1);
        assertThat(peers.path("verdicts").path("UNSOUND").asLong()).isEqualTo(1);
        assertThat(peers.path("reasons").path("MISSED_SIGNAL").asLong()).isEqualTo(1);
        assertThat(peers.path("delayHours").asInt()).isEqualTo(1);
        assertThat(mvc.perform(get("/api/runs/run-000000000000/steps/1/peer-assessments")).andReturn()
                .getResponse().getStatus()).as("an unknown run").isEqualTo(404);
    }

    private String peerRun(String visitor, String sha, String setting, String forced) {
        String runId = "run-" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        jdbc.update("""
                insert into run (run_id, scenario_key, scenario_version, employee_key, principal, organization_id,
                    tenant_id, client_ip, device, company_time, status, live_visitor_hash, live_run, scenario_sha256,
                    setting_hash, forced_action)
                values (?, 'A3', 1, 'adm-a', ?, 'org', 'tenant', '10.40.12.77', 'test', now(), 'COMPLETED', ?, true,
                    ?, ?, ?)""", runId, "v" + runId, visitor, sha, setting, forced);
        return runId;
    }

    private void assessed(String runId, String visitor, String verdict, String reasons, Instant at) {
        jdbc.update("""
                insert into visitor_assessment (run_id, step_no, visitor_hash, verdict, reasons, assessed_at)
                values (?, 1, ?, ?, cast(? as jsonb), ?)""", runId, visitor, verdict, reasons, Timestamp.from(at));
    }

    private MockHttpServletResponse assess(Cookie visitor, String runId, int step, String verdict)
            throws Exception {
        return mvc.perform(post("/api/runs/" + runId + "/steps/" + step + "/assessment").with(csrf()).cookie(visitor)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"verdict\":\"" + verdict + "\",\"reasons\":[\"MISSED_SIGNAL\",\"DISAGREE_TRUTH\"]}"))
                .andReturn().getResponse();
    }

    private Cookie visitor() throws Exception {
        return mvc.perform(get("/api/visitor")).andExpect(status().isOk()).andReturn().getResponse()
                .getCookie(VisitorCookies.NAME);
    }

    private String hash(Cookie cookie) {
        return new VisitorCookies(SIGNING_KEY).verify(cookie.getValue()).map(VisitorCookies::hash).orElseThrow();
    }

    private void run(String runId, String visitor) {
        jdbc.update("""
                insert into run (run_id, scenario_key, scenario_version, employee_key, principal, organization_id,
                    tenant_id, client_ip, device, company_time, status, live_visitor_hash, live_run)
                values (?, 'A3', 1, 'adm-a', ?, 'org', 'tenant', '10.40.12.77', 'test', now(), 'COMPLETED', ?, true)""",
                runId, "v" + runId, visitor);
        jdbc.update("""
                insert into run_decision (request_id, run_id, step_no, final_action, unresolved, applied, records,
                    events)
                values (?, ?, 1, 'ALLOW', false, 'NEXT_REQUEST', '[]'::jsonb, '[]'::jsonb)""",
                UUID.randomUUID(), runId);
    }

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
