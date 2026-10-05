package io.contexa.showcase.portal.share;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.replay.PairDefinition.SceneKind;
import io.contexa.showcase.portal.replay.ReplayStore;
import io.contexa.showcase.portal.spec.ExecutionSpec;
import io.contexa.showcase.portal.spec.ExecutionSpecStore;
import io.contexa.showcase.portal.visitor.VisitorCookies;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
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
 * Deck p.15 on the end screen's result and the share card: scored once on the server from the published recording
 * and the visitor's votes, the same result always gives the same card, and neither the card, its link page nor the
 * table holds anything about the visitor (P5-PRV-01, share card part). Skipped without Docker.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(properties = "showcase.public-url=https://demo.example.test")
@AutoConfigureMockMvc
class ShareIntegrationTest {

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
    ExecutionSpecStore specs;

    @Autowired
    ReplayStore replays;

    @Autowired
    ObjectMapper json;

    private String attackRun;

    /** A published pair A3: control D delivers both scenes (attack missed, legitimate passed): Contexa 1/2. */
    @BeforeEach
    void publishedPair() {
        jdbc.update("delete from share_card");
        jdbc.update("update replay_record set status = 'RETIRED' where status = 'PUBLISHED'");
        String spec = specs.record(new ExecutionSpec("test-commit", "0.1.0", "ENFORCE",
                Map.of("POST /api/projects/*/exports", "sync"), "gpt-5-nano", "text-embedding-3-small", 1024,
                "p".repeat(64), null, "r".repeat(64), null, "UTC"));
        attackRun = run("A3", spec, false);
        String legitimateRun = run("A3T", spec, true);
        replays.publish(record(SceneKind.ATTACK, "A3", spec, attackRun));
        replays.publish(record(SceneKind.LEGITIMATE, "A3T", spec, legitimateRun));
    }

    @Test
    void theFirstCallCarriesOverToTheLookAlikeSceneAndContexaIsScoredFromTheRecording() throws Exception {
        JsonNode anonymous = result(null);
        assertThat(anonymous.path("mine").isNull()).isTrue();
        assertThat(anonymous.path("contexa").path("hits").asInt()).isEqualTo(1);
        assertThat(anonymous.path("contexa").path("total").asInt()).isEqualTo(2);

        Cookie visitor = visitorWhoVoted("BLOCK");
        JsonNode voted = result(visitor);
        assertThat(voted.path("mine").path("hits").asInt()).isEqualTo(1);
        assertThat(voted.path("mine").path("total").asInt()).isEqualTo(2);
        JsonNode legitimate = voted.path("scenes").get(1);
        assertThat(legitimate.path("kind").asText()).isEqualTo("LEGITIMATE");
        assertThat(legitimate.path("choice").asText()).isEqualTo("BLOCK");
        assertThat(legitimate.path("carriedOver").asBoolean()).isTrue();
        assertThat(legitimate.path("myCorrect").asBoolean()).isFalse();
        assertThat(voted.path("scenes").get(0).path("contexaCorrect").asBoolean()).as("the attack's data left")
                .isFalse();

        jdbc.update("update run_arm_result set http_status = 403, outcome = 'REFUSED', delivered_items = 0 "
                + "where run_id = ? and control = 'D'", attackRun);
        jdbc.update("update run_decision set final_action = 'BLOCK' where run_id = ?", attackRun);
        assertThat(result(visitor).path("contexa").path("hits").asInt()).isEqualTo(2);
        mvc.perform(get("/api/results/NOPE")).andExpect(status().isNotFound());
    }

    @Test
    void theSameResultGivesTheSameCardAndTheCardCarriesTheResultOnly() throws Exception {
        Cookie first = visitorWhoVoted("BLOCK");
        Cookie second = visitorWhoVoted("BLOCK");
        JsonNode shared = share(first, "ko");
        String key = shared.path("shareKey").asText();
        assertThat(key).matches("[A-Za-z0-9]{10}");
        assertThat(shared.path("url").asText()).isEqualTo("https://demo.example.test/s/" + key);
        assertThat(share(second, "ko").path("shareKey").asText()).as("same result, same card").isEqualTo(key);
        assertThat(share(null, "ko").path("shareKey").asText()).as("Contexa only").isNotEqualTo(key);
        assertThat(share(first, "en").path("shareKey").asText()).isNotEqualTo(key);
        assertThat(jdbc.queryForObject("select count(*) from share_card", Integer.class)).isEqualTo(3);
        assertThat(jdbc.queryForList("select column_name from information_schema.columns "
                + "where table_name = 'share_card'", String.class)).noneMatch(column -> column.contains("visitor"));

        String page = mvc.perform(get("/s/" + key)).andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString();
        assertThat(page).contains("<meta property=\"og:image\" content=\"https://demo.example.test/s/" + key
                        + "/card.png\">", "twitter:card", "나 1/2 · Contexa 1/2", "noindex")
                .doesNotContain(first.getValue().substring(0, first.getValue().indexOf('.')), "<script");
        byte[] png = mvc.perform(get("/s/" + key + "/card.png")).andExpect(status().isOk()).andReturn()
                .getResponse().getContentAsByteArray();
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(png));
        assertThat(image.getWidth()).isEqualTo(1200);
        assertThat(image.getHeight()).isEqualTo(630);

        mvc.perform(get("/s/NOTAKEY000")).andExpect(status().isNotFound());
        mvc.perform(get("/s/..%2Fetc")).andExpect(status().is4xxClientError());
        mvc.perform(post("/api/shares").with(csrf()).contentType(MediaType.APPLICATION_JSON)
                .content("{\"pairKey\":\"A3\",\"language\":\"fr\"}")).andExpect(status().isBadRequest());
        mvc.perform(post("/api/shares").contentType(MediaType.APPLICATION_JSON)
                .content("{\"pairKey\":\"A3\",\"language\":\"ko\"}")).andExpect(status().isForbidden());
    }

    private Cookie visitorWhoVoted(String choice) throws Exception {
        MvcResult visitor = mvc.perform(get("/api/visitor")).andExpect(status().isOk()).andReturn();
        Cookie cookie = visitor.getResponse().getCookie(VisitorCookies.NAME);
        mvc.perform(post("/api/predictions").with(csrf()).cookie(cookie).contentType(MediaType.APPLICATION_JSON)
                .content("{\"scene\":\"A3:ATTACK\",\"choice\":\"" + choice + "\"}")).andExpect(status().isCreated());
        return cookie;
    }

    private JsonNode result(Cookie visitor) throws Exception {
        MockHttpServletRequestBuilder request = get("/api/results/A3");
        if (visitor != null) {
            request.cookie(visitor);
        }
        return json.readTree(mvc.perform(request).andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString());
    }

    private JsonNode share(Cookie visitor, String language) throws Exception {
        MockHttpServletRequestBuilder request = post("/api/shares").with(csrf()).contentType(MediaType.APPLICATION_JSON)
                .content("{\"pairKey\":\"A3\",\"language\":\"" + language + "\"}");
        if (visitor != null) {
            request.cookie(visitor);
        }
        return json.readTree(mvc.perform(request).andExpect(status().isCreated()).andReturn().getResponse()
                .getContentAsString());
    }

    private String run(String scenario, String spec, boolean approved) {
        String runId = "run-" + UUID.randomUUID().toString().substring(0, 12);
        Timestamp companyTime = Timestamp.from(Instant.parse("2026-09-30T03:17:00Z"));
        jdbc.update("""
                        insert into run (run_id, scenario_key, scenario_version, employee_key, principal, organization_id,
                                         tenant_id, client_ip, device, company_time, status, spec_hash)
                        values (?, ?, 1, 'adm-a', 'v000000000000-adm-a', 'org-x', 'tenant-x', '10.40.12.9', 'Device',
                                ?, 'COMPLETED', ?)""", runId, scenario, companyTime, spec);
        Map<String, Object[]> arms = Map.of(
                "A", new Object[]{200, "DELIVERED", 4831, null},
                "B", new Object[]{200, "DELIVERED", 4831, null},
                "C1", new Object[]{403, "REFUSED", 0, "C1-NIGHT"},
                "C2", approved ? new Object[]{200, "DELIVERED", 4831, null}
                        : new Object[]{403, "REFUSED", 0, "C2-NO-CONTEXT"},
                "D", new Object[]{200, "DELIVERED", 4831, null});
        String dRequest = UUID.randomUUID().toString();
        for (Map.Entry<String, Object[]> arm : arms.entrySet()) {
            Object[] values = arm.getValue();
            jdbc.update("""
                            insert into run_arm_result (run_id, step_no, control, request_id, operation, method, path,
                                                        company_time, http_status, outcome, delivered_items, rule_id,
                                                        elapsed_ms, sent_at)
                            values (?, 1, ?, cast(? as uuid), 'EXPORT', 'POST', '/api/projects/GB-500/exports', ?, ?, ?,
                                    ?, ?, 10, now())""",
                    runId, arm.getKey(), "D".equals(arm.getKey()) ? dRequest : UUID.randomUUID().toString(),
                    companyTime, values[0], values[1], values[2], values[3]);
        }
        jdbc.update("""
                insert into run_decision (request_id, run_id, step_no, final_action, applied, records, events)
                values (cast(? as uuid), ?, 1, 'ALLOW', 'BEFORE_RESPONSE', '[]'::jsonb, '[]'::jsonb)""",
                dRequest, runId);
        jdbc.update("insert into run_business_evidence (run_id, exports, rule_decisions) values (?, '[]'::jsonb, "
                + "'[]'::jsonb)", runId);
        return runId;
    }

    private String record(SceneKind scene, String scenario, String spec, String runId) {
        String recordId = "rec-share-" + scene.name().toLowerCase() + "-" + UUID.randomUUID().toString().substring(0, 8);
        replays.save(new ReplayStore.RecordRow(recordId, "A3", scene, scenario, 1, spec, 1, 1, runId, "signature",
                "DRAFT", null, null), List.of(new ReplayStore.RecordedRun(runId, 1, "signature")));
        return recordId;
    }

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
