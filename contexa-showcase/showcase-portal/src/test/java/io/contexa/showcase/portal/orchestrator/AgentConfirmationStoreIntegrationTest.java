package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.agent.AgentTaskProof;
import io.contexa.showcase.portal.agent.AgentWork;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent A7-3: the confirmation control D asked of an agent's work is stored with its run and read back with the
 * work; the agent group finds an operator's latest recording of a case definition, never a visitor's. Skipped without
 * Docker.
 */
@Testcontainers(disabledWithoutDocker = true)
class AgentConfirmationStoreIntegrationTest {

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

    private static final Instant AT = Instant.parse("2026-10-24T05:00:00Z");
    private static final String SHA = "c".repeat(64);

    private static RunStore store;
    private static JdbcTemplate jdbc;

    @BeforeAll
    static void migrate() {
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration/portal").cleanDisabled(true).load().migrate();
        DriverManagerDataSource dataSource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(),
                POSTGRES.getUsername(), POSTGRES.getPassword());
        jdbc = new JdbcTemplate(dataSource);
        store = new RunStore(new NamedParameterJdbcTemplate(dataSource), new ObjectMapper().findAndRegisterModules());
    }

    @Test
    void theConfirmationIsStoredWithTheRunAndReadWithItsWork() {
        start("run-agent-cfm", null);
        work("run-agent-cfm");
        ControlSession.StepOutcome resend = new ControlSession.StepOutcome("req-2", "GET",
                "/api/projects/HX-310/documents?type=DRAWING", AT, 200, "DELIVERED", 5, null, null, "{}", 30, AT, null);
        ControlSession.StepOutcome reuse = new ControlSession.StepOutcome("req-3", "GET",
                "/api/projects/HX-310/documents?type=DRAWING", AT, 403, "REFUSED", 0, "AGENT_CONFIRMATION_USED", null,
                "{}", 20, AT, null);

        store.agentConfirmation("run-agent-cfm", 1, new ControlSession.AgentConfirmationTrace("cfm-1",
                "DELEGATION_ENDED", AT.plusSeconds(600).toString(), "APPROVE", null, AT, AT.plusSeconds(40), 302,
                new ControlSession.AgentConfirmationStatus(200, "APPROVED", "authz-7", null, null, "DELEGATION_ENDED",
                        "GET", "/api/projects/HX-310/documents?type=DRAWING"), resend, reuse, null, null, null));

        Map<String, Object> stored = store.agentConfirmation("run-agent-cfm").orElseThrow();
        assertThat(stored).containsEntry("confirmationId", "cfm-1").containsEntry("decision", "APPROVE")
                .containsEntry("trigger", "DELEGATION_ENDED");
        assertThat(((JsonNode) stored.get("after")).path("authorizationId").asText()).isEqualTo("authz-7");
        assertThat(((JsonNode) stored.get("resend")).path("deliveredItems").asInt()).isEqualTo(5);
        assertThat(((JsonNode) stored.get("reuse")).path("ruleId").asText()).isEqualTo("AGENT_CONFIRMATION_USED");
        assertThat(stored.get("other")).isNull();
        @SuppressWarnings("unchecked")
        Map<String, Object> confirmation = (Map<String, Object>) store.agentTaskSummary("run-agent-cfm").orElseThrow()
                .get("confirmation");
        assertThat(confirmation).containsEntry("confirmationId", "cfm-1");
        assertThat(stored.get("personRequest")).isNull();
        assertThat(stored.get("retries")).isNull();
        assertThat(store.agentConfirmation("run-without-confirmation")).isEmpty();
    }

    @Test
    void anUnansweredConfirmationKeepsTheAgentsRetriesAndThePersonsOwnRequest() {
        start("run-agent-silent", null);
        work("run-agent-silent");
        ControlSession.StepOutcome limited = new ControlSession.StepOutcome("req-122", "GET",
                "/api/projects/HX-310/documents", AT, 429, "REFUSED", 0, "AGENT_CALL_LIMIT", null,
                "{\"retryAfterSeconds\":38}", 5, AT, null);
        ControlSession.StepOutcome person = new ControlSession.StepOutcome("req-200", "GET",
                "/api/projects/HX-310/documents", AT, 200, "DELIVERED", 5, null, null, "[]", 30, AT, null);
        Map<String, Integer> outcomes = new LinkedHashMap<>();
        outcomes.put("403 AGENT_CONFIRMATION_REQUIRED", 120);
        outcomes.put("429 AGENT_CALL_LIMIT", 10);

        store.agentConfirmation("run-agent-silent", 1, new ControlSession.AgentConfirmationTrace("cfm-2",
                "DELEGATION_ENDED", AT.plusSeconds(900).toString(), "SILENT", null, AT, null, null, null, null, null,
                null, person, new ControlSession.RetryStorm(130, outcomes, 121, limited, 39L, null)));

        Map<String, Object> stored = store.agentConfirmation("run-agent-silent").orElseThrow();
        assertThat(stored).containsEntry("decision", "SILENT");
        JsonNode retries = (JsonNode) stored.get("retries");
        assertThat(retries.path("sent").asInt()).isEqualTo(130);
        assertThat(retries.path("outcomes").path("429 AGENT_CALL_LIMIT").asInt()).isEqualTo(10);
        assertThat(retries.path("firstLimitedAt").asInt()).isEqualTo(121);
        assertThat(retries.path("firstLimited").path("ruleId").asText()).isEqualTo("AGENT_CALL_LIMIT");
        assertThat(retries.path("waitedSeconds").asLong()).isEqualTo(39);
        assertThat(((JsonNode) stored.get("personRequest")).path("deliveredItems").asInt()).isEqualTo(5);
        assertThat(stored.get("resend")).isNull();
    }

    @Test
    void theLatestRecordingIsAnOperatorsCompletedRunOfTheSameDefinition() {
        start("run-agent-rec1", null);
        work("run-agent-rec1");
        store.finish("run-agent-rec1", "COMPLETED", null, Map.of());
        start("run-agent-live", "d".repeat(64));
        work("run-agent-live");
        store.finish("run-agent-live", "COMPLETED", null, Map.of());
        start("run-agent-fail", null);
        work("run-agent-fail");
        store.finish("run-agent-fail", "FAILED", "boom", Map.of());

        assertThat(store.latestRecordedAgentRun(SHA)).hasValueSatisfying(row ->
                assertThat(row.get("run_id")).isEqualTo("run-agent-rec1"));
        assertThat(store.latestRecordedAgentRun("e".repeat(64))).isEmpty();
    }

    private static void start(String runId, String visitor) {
        jdbc.update("insert into visitor (visitor_hash) values (?) on conflict do nothing", "d".repeat(64));
        store.start(new RunStore.RunStart(runId, "T5", 1, "E-0042", "kim", null, "org", "tenant", "10.0.0.1",
                "laptop", AT, null, visitor, "{}", SHA));
    }

    private static void work(String runId) {
        AgentWork.Transcript work = new AgentWork.Transcript("gpt-6-luna", "prompt", "Prepare the weekly report",
                List.of(), "Pending confirmation.", "ANSWERED", null, Map.of("totalTokens", 1100), AT,
                AT.plusSeconds(4));
        AgentTaskProof.Proof proof = new AgentTaskProof.Proof(true, null, "Pending confirmation.", "ANSWERED", true,
                List.of("HX-310"), null, 1, 1, 1, Map.of("D", new AgentTaskProof.Control(0, 0, 0, 0, 1, "REFUSED")),
                Map.of("totalTokens", 1100));
        store.agentTask(runId, "DELEGATED_AGENT", work, proof);
    }
}
