package io.contexa.showcase.portal.replay;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.combination.Combination;
import io.contexa.showcase.portal.combination.CombinationService;
import io.contexa.showcase.portal.combination.CombinationStore;
import io.contexa.showcase.portal.live.LiveAllotment;
import io.contexa.showcase.portal.live.LiveQuota;
import io.contexa.showcase.portal.orchestrator.Measurements;
import io.contexa.showcase.portal.replay.PairDefinition.SceneKind;
import io.contexa.showcase.portal.spec.ExecutionSpec;
import io.contexa.showcase.portal.spec.ExecutionSpecStore;
import io.contexa.showcase.portal.visitor.VisitorCookies;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDate;
import java.time.YearMonth;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.offset;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Visitor API and recorded replays on the real portal schema (P2-DB-01, P2-BE-01): no address column, one prediction
 * per visitor and scene, forged cookies refused, a replay served only when both scenes are published and consistent.
 * Skipped without Docker.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest
@AutoConfigureMockMvc
class ReplayAndVisitorIntegrationTest {

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
    NamedParameterJdbcTemplate namedJdbc;

    @Autowired
    ExecutionSpecStore specs;

    @Autowired
    ReplayStore replays;

    @Autowired
    ReplayConsistency consistency;

    @Autowired
    ObjectMapper json;

    @Test
    void visitorAndPredictionTablesHoldNoAddress() {
        List<String> columns = jdbc.queryForList("""
                select column_name from information_schema.columns
                 where table_name in ('visitor', 'prediction')""", String.class);

        assertThat(columns).isNotEmpty().noneMatch(column -> column.contains("ip") || column.contains("address")
                || column.contains("agent"));
    }

    @Test
    void aVisitorPredictsEachSceneOnceAndAForgedCookieIsRefused() throws Exception {
        MvcResult visitor = mvc.perform(get("/api/visitor")).andExpect(status().isOk()).andReturn();
        Cookie cookie = visitor.getResponse().getCookie(VisitorCookies.NAME);
        assertThat(cookie).isNotNull();
        assertThat(cookie.isHttpOnly()).isTrue();
        String body = "{\"scene\":\"A3:ATTACK\",\"choice\":\"BLOCK\"}";

        mvc.perform(post("/api/predictions").cookie(cookie).contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden());
        mvc.perform(post("/api/predictions").with(csrf()).cookie(cookie).contentType(MediaType.APPLICATION_JSON)
                .content(body)).andExpect(status().isCreated());
        MvcResult again = mvc.perform(post("/api/predictions").with(csrf()).cookie(cookie)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"scene\":\"A3:ATTACK\",\"choice\":\"ALLOW\"}"))
                .andExpect(status().isConflict()).andReturn();
        assertThat(json.readTree(again.getResponse().getContentAsString()).path("choice").asText())
                .as("the first vote stays").isEqualTo("BLOCK");

        String value = cookie.getValue();
        Cookie forged = new Cookie(VisitorCookies.NAME, value.substring(0, value.indexOf('.') + 1) + "forged");
        mvc.perform(post("/api/predictions").with(csrf()).cookie(forged).contentType(MediaType.APPLICATION_JSON)
                .content(body)).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/predictions").with(csrf()).cookie(cookie).contentType(MediaType.APPLICATION_JSON)
                .content("{\"scene\":\"NOPE:ATTACK\",\"choice\":\"BLOCK\"}")).andExpect(status().isBadRequest());
        assertThat(jdbc.queryForObject("select count(*) from prediction", Integer.class)).isEqualTo(1);
    }

    @Test
    void aReplayIsServedOnlyWhenBothScenesArePublishedAndConsistent() throws Exception {
        String spec = specs.record(spec());
        String attackRun = run("A3", spec, false);
        String legitimateRun = run("A3T", spec, true);
        String attack = record(SceneKind.ATTACK, "A3", spec, attackRun);
        String legitimate = record(SceneKind.LEGITIMATE, "A3T", spec, legitimateRun);

        mvc.perform(get("/api/replays/A3")).andExpect(status().isNotFound());
        replays.publish(attack);
        mvc.perform(get("/api/replays/A3")).andExpect(status().isNotFound());
        replays.publish(legitimate);

        JsonNode pair = json.readTree(mvc.perform(get("/api/replays/A3")).andExpect(status().isOk()).andReturn()
                .getResponse().getContentAsString());
        JsonNode scene = pair.path("scenes").get(0);
        assertThat(scene.path("kind").asText()).isEqualTo("ATTACK");
        assertThat(scene.path("agreeing").asInt()).isEqualTo(1);
        assertThat(scene.path("layers")).extracting(layer -> layer.path("control").asText())
                .containsExactly("A", "B", "C1", "C2", "D");
        JsonNode night = scene.path("layers").get(2);
        assertThat(night.path("verdict").isNull()).as("a rule control makes no verdict (survey #25)").isTrue();
        assertThat(night.path("ruleId").asText()).isEqualTo("C1-NIGHT");
        assertThat(night.path("httpStatus").asInt()).isEqualTo(403);
        // F-13: the ground truth is there whatever company facts the scene has; this run predates the stored
        // definition, so it comes from the catalog's definition of the same version.
        assertThat(scene.path("truth").path("source").asText()).isEqualTo("CATALOG_SAME_VERSION");
        assertThat(scene.path("truth").path("classification").asText()).isEqualTo("THREAT");
        assertThat(scene.path("truth").path("rationale").path("ko").asText()).isNotBlank();
        JsonNode engine = scene.path("layers").get(4).path("evidence");
        assertThat(engine.path("decisionId").asText()).isEqualTo("00000000-0000-0000-0000-00000000000d");
        assertThat(engine.path("responseMs").asLong()).isEqualTo(1702);
        assertThat(engine.path("timeline")).extracting(event -> event.path("type").asText() + "@"
                + event.path("atMs").asLong()).containsExactly("CONTEXT_COLLECTED@38", "LAYER1_START@38",
                "LAYER1_COMPLETE@1666", "DECISION_APPLIED@1666");
        assertThat(engine.path("timeline").get(2).path("elapsedMs").asLong()).isEqualTo(1627);
        assertThat(scene.path("layers").get(2).path("evidence").path("timeline")).isEmpty();
        assertThat(scene.path("companyFacts").get(0).path("code").asText()).isEqualTo("NOT_ASSIGNED");
        assertThat(pair.path("scenes").get(1).path("companyFacts").get(1).path("code").asText())
                .isEqualTo("APPROVAL_COVERS");
        mvc.perform(get("/api/specs/" + spec)).andExpect(status().isOk());
        // The R1 scoring contract draft is not served to visitors (ADR-28).
        mvc.perform(get("/api/contract")).andExpect(status().isForbidden());

        assertThat(consistency.check(null)).allMatch(ReplayConsistency.Finding::consistent);
        jdbc.update("update run_arm_result set outcome = 'CUT' where run_id = ? and control = 'D'", attackRun);
        assertThat(consistency.check(null)).anyMatch(finding -> finding.problems().stream()
                .anyMatch(problem -> problem.contains("is cut without an engine BLOCK")));
        jdbc.update("update run_decision set final_action = 'BLOCK' where run_id = ?", attackRun);
        assertThat(consistency.check(null)).allMatch(ReplayConsistency.Finding::consistent);
        jdbc.update("update run set forced_action = 'CHALLENGE' where run_id = ?", attackRun);
        assertThat(consistency.check(null)).anyMatch(finding -> finding.problems().stream()
                .anyMatch(problem -> problem.contains("development-only forced decision")));
        jdbc.update("update run set forced_action = null where run_id = ?", attackRun);
        jdbc.update("update execution_spec set chat_model = 'altered' where spec_hash = ?", spec);
        assertThat(consistency.check(null)).anyMatch(finding -> finding.problems().stream()
                .anyMatch(problem -> problem.contains("recomputes")));
    }

    /** Events in the shape D stores them; the times give 38 ms and 1,666 ms after the send time used above. */
    private static final String ENGINE_EVENTS = """
            [{"type": "CONTEXT_COLLECTED", "layer": null, "action": null, "elapsedMs": null,
              "observedAt": "2026-10-05T03:57:37.662017600Z"},
             {"type": "LAYER1_START", "layer": "LAYER1", "action": null, "elapsedMs": null,
              "observedAt": "2026-10-05T03:57:37.662017600Z"},
             {"type": "LAYER1_COMPLETE", "layer": "LAYER1", "action": "ALLOW", "elapsedMs": 1627,
              "observedAt": "2026-10-05T03:57:39.289861700Z"},
             {"type": "DECISION_APPLIED", "layer": "LAYER1", "action": "ALLOW", "elapsedMs": null,
              "observedAt": "2026-10-05T03:57:39.289861700Z"}]""";

    /** P4-DB-01: one record per cell and versions, the first completed real run wins, forced runs never count. */
    @Test
    void aCombinationKeepsItsFirstCompletedRealRunOnly() {
        CombinationStore store = new CombinationStore(namedJdbc);
        CombinationService service = new CombinationService(null, null, null, store, replays, null,
                Clock.systemUTC());
        Combination cell = Combination.parse("adm-a.DAWN.4831.MATCH.USUAL");
        String version = "v".repeat(64);
        String first = combinationRun(cell.key(), "COMPLETED", null);
        String second = combinationRun(cell.key(), "COMPLETED", null);

        assertThat(service.keep(cell, version, combinationRun(cell.key(), "COMPLETED", "CHALLENGE"), "x".repeat(64)))
                .as("forced").isFalse();
        assertThat(service.keep(cell, version, combinationRun(cell.key(), "FAILED", null), "x".repeat(64)))
                .as("failed").isFalse();
        assertThat(service.keep(cell, version, combinationRun("A3", "COMPLETED", null), "x".repeat(64)))
                .as("another scenario").isFalse();
        assertThat(service.keep(cell, version, first, "x".repeat(64))).isTrue();
        assertThat(service.keep(cell, version, second, "y".repeat(64))).as("the first run wins").isFalse();
        assertThat(store.find(cell.key(), version)).get().extracting(CombinationStore.RecordRow::runId)
                .isEqualTo(first);
        assertThat(store.find(cell.key(), "w".repeat(64))).as("another version key").isEmpty();
        assertThat(service.keep(cell, "w".repeat(64), second, "y".repeat(64))).isTrue();
    }

    /** P4-BE-03 and P2-DB-01: visitor and address limits per day, with the address kept only as a daily keyed hash. */
    @Test
    void theDailyLimitsCountVisitorsAndAddressesWithoutKeepingTheAddress() {
        DayClock clock = new DayClock(Instant.parse("2026-10-05T08:00:00Z"));
        LiveQuota quota = new LiveQuota(namedJdbc, SIGNING_KEY, 2, 3, clock);
        String address = "203.0.113.7";

        assertThat(quota.take("a".repeat(64), address)).isNull();
        assertThat(quota.take("a".repeat(64), address)).isNull();
        assertThat(quota.take("a".repeat(64), address)).isEqualTo(LiveQuota.Refusal.VISITOR_LIMIT);
        assertThat(quota.remaining("a".repeat(64))).isZero();
        assertThat(quota.take("b".repeat(64), address)).as("third run from the address").isNull();
        assertThat(quota.take("c".repeat(64), address)).as("cookie cleared, same address")
                .isEqualTo(LiveQuota.Refusal.ADDRESS_LIMIT);
        quota.giveBack("b".repeat(64), address);
        assertThat(quota.take("c".repeat(64), address)).isNull();

        List<String> stored = jdbc.queryForList("select subject_hash from live_quota where subject_kind = 'ADDRESS'",
                String.class);
        assertThat(stored).singleElement().satisfies(hash -> assertThat(hash).hasSize(64).doesNotContain("203"));
        String today = stored.get(0);
        clock.now = clock.now.plus(Duration.ofDays(1));
        assertThat(quota.take("a".repeat(64), address)).as("a new day").isNull();
        assertThat(jdbc.queryForList("select subject_hash from live_quota where subject_kind = 'ADDRESS'",
                String.class)).hasSize(2).doesNotHaveDuplicates().contains(today);
    }

    /** P4-BE-04: the allotment counts only live runs' usage, alerts once at 80 percent and stops at 100 percent. */
    @Test
    void theDailyAllotmentAlertsOnceAndStopsWhenSpent() {
        LocalDate day = LocalDate.now(ZoneOffset.UTC);
        double perDay = 0.01;
        LiveAllotment allotment = new LiveAllotment(namedJdbc, new Measurements.Prices(0.05, 0.40, 0.02, "test"),
                perDay * YearMonth.from(day).lengthOfMonth(), Clock.systemUTC());
        String spec = specs.record(spec());
        String live = run("A3T", spec, true);
        String recording = run("A3T", spec, true);
        jdbc.update("update run set live_visitor_hash = ?, live_run = true where run_id = ?", "v".repeat(64), live);
        cost(recording, 1_000_000, 1_000_000);

        assertThat(allotment.state().spentUsd()).as("recordings do not count").isZero();
        cost(live, 150_000, 0);
        assertThat(allotment.state().alerted()).as("75 percent").isFalse();
        cost(live, 0, 3_000);
        LiveAllotment.State alerted = allotment.state();
        assertThat(alerted.spentUsd()).as("87 percent").isCloseTo(0.0087, offset(0.000001));
        assertThat(alerted.alerted()).isTrue();
        assertThat(alerted.exhausted()).isFalse();
        cost(live, 0, 4_000);
        assertThat(allotment.state().exhausted()).as("103 percent").isTrue();
        assertThat(jdbc.queryForObject("select count(*) from live_allotment_alert", Integer.class)).isEqualTo(1);
    }

    private void cost(String runId, long promptTokens, long completionTokens) {
        jdbc.update("""
                        insert into cost_ledger (entry_id, run_id, kind, model, prompt_tokens, completion_tokens,
                                                 total_tokens)
                        values (?, ?, 'CHAT', 'gpt-5-nano', ?, ?, ?)""", UUID.randomUUID(), runId, promptTokens,
                completionTokens, promptTokens + completionTokens);
    }

    private static final class DayClock extends Clock {

        private Instant now;

        DayClock(Instant now) {
            this.now = now;
        }

        @Override
        public ZoneOffset getZone() {
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

    private String combinationRun(String scenario, String status, String forced) {
        String runId = "run-" + UUID.randomUUID().toString().substring(0, 12);
        jdbc.update("""
                        insert into run (run_id, scenario_key, scenario_version, employee_key, principal, organization_id,
                                         tenant_id, client_ip, device, company_time, status, forced_action)
                        values (?, ?, 1, 'adm-a', 'v000000000000-adm-a', 'org-x', 'tenant-x', '10.40.12.9', 'Device',
                                now(), ?, ?)""", runId, scenario, status, forced);
        return runId;
    }

    private static ExecutionSpec spec() {
        return new ExecutionSpec("test-commit", "0.1.0", "ENFORCE", Map.of("POST /api/projects/*/exports", "sync"),
                "gpt-5-nano", "text-embedding-3-small", 1024, "p".repeat(64), null, "r".repeat(64), null, "UTC", null);
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
                "A", new Object[]{200, "DELIVERED", 4831, null, null},
                "B", new Object[]{200, "DELIVERED", 4831, null, null},
                "C1", new Object[]{403, "REFUSED", 0, "C1-NIGHT", "night"},
                "C2", approved ? new Object[]{200, "DELIVERED", 4831, null, null}
                        : new Object[]{403, "REFUSED", 0, "C2-NO-CONTEXT", "no context"},
                "D", new Object[]{200, "DELIVERED", 4831, null, null});
        String contextRequest = UUID.randomUUID().toString();
        for (Map.Entry<String, Object[]> arm : arms.entrySet()) {
            String requestId = "D".equals(arm.getKey()) ? "00000000-0000-0000-0000-00000000000d"
                    : "C2".equals(arm.getKey()) ? contextRequest : UUID.randomUUID().toString();
            Object[] values = arm.getValue();
            jdbc.update("""
                            insert into run_arm_result (run_id, step_no, control, request_id, operation, method, path,
                                                        company_time, http_status, outcome, delivered_items, rule_id,
                                                        reason, elapsed_ms, sent_at)
                            values (?, 1, ?, cast(? as uuid), 'EXPORT', 'POST', '/api/projects/GB-500/exports', ?, ?, ?,
                                    ?, ?, ?, 10, now())""",
                    runId, arm.getKey(), requestId, companyTime, values[0], values[1], values[2], values[3], values[4]);
        }
        if ("A3".equals(scenario)) {
            jdbc.update("update run_arm_result set sent_at = ?, elapsed_ms = 1702 where run_id = ? and control = 'D'",
                    Timestamp.from(Instant.parse("2026-10-05T03:57:37.623134Z")), runId);
            jdbc.update("""
                    insert into run_decision (request_id, run_id, step_no, final_action, applied, records, events)
                    values ('00000000-0000-0000-0000-00000000000d', ?, 1, 'ALLOW', 'BEFORE_RESPONSE', '[]'::jsonb,
                            cast(? as jsonb))""", runId, ENGINE_EVENTS);
        }
        String facts = approved
                ? "{\"assigned\": {\"assigned\": false}, \"approval\": {\"covered\": true, \"purpose\": \"PROJECT_TRANSFER\"}}"
                : "{\"assigned\": {\"assigned\": false}, \"approval\": {\"covered\": false}}";
        jdbc.update("insert into run_business_evidence (run_id, exports, rule_decisions) values (?, '[]'::jsonb, "
                        + "cast(? as jsonb))", runId,
                "[{\"control\": \"C2\", \"request_id\": \"" + contextRequest + "\", \"facts\": "
                        + json(facts) + "}]");
        return runId;
    }

    private String json(String text) {
        try {
            return json.writeValueAsString(text);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String record(SceneKind scene, String scenario, String spec, String runId) {
        String recordId = "rec-test-" + scene.name().toLowerCase() + "-" + UUID.randomUUID().toString().substring(0, 8);
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
