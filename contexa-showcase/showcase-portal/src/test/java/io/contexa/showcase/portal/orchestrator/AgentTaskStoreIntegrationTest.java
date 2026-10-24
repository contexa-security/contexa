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
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** docs/agent A7-2e: an agent task's work and proof are stored with its run and read back whole. Skipped without Docker. */
@Testcontainers(disabledWithoutDocker = true)
class AgentTaskStoreIntegrationTest {

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

    private static final Instant AT = Instant.parse("2026-10-23T05:00:00Z");

    private static RunStore store;
    private static JdbcTemplate jdbc;
    private final ObjectMapper json = new ObjectMapper().findAndRegisterModules();

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
    void theWorkAndWhatItProvesAreStoredWithTheRun() throws Exception {
        store.start(new RunStore.RunStart("run-agent-task", "T1", 1, "E-0042", "kim", null, "org", "tenant",
                "10.0.0.1", "laptop", AT, null, null, "{}", "a".repeat(64)));
        AgentWork.Answer answer = new AgentWork.Answer(1, "/api/documents/DOC-7", 200, "DELIVERED", null, "{}",
                Map.of("D", "DELIVERED"), Map.of("D", 0), Map.of("D", "{}"));
        AgentWork.Transcript work = new AgentWork.Transcript("gpt-6-luna", "prompt", "Summarize the rotor drawing",
                List.of(new AgentWork.ToolCall(1, "readDocument", Map.of("documentKey", "DOC-7"), AT, true, answer,
                        "HTTP 200\n{}")), "Revision 3.", "ANSWERED", null, Map.of("totalTokens", 330), AT,
                AT.plusSeconds(12));
        AgentTaskProof.Proof proof = new AgentTaskProof.Proof(true, "summary", "Revision 3.", "ANSWERED", true,
                List.of("HX-310"), null, 1, 1, 1, Map.of("D", new AgentTaskProof.Control(0, 0, 0, 0, 1, "REFUSED")),
                Map.of("totalTokens", 330));

        store.agentTask("run-agent-task", "DELEGATED_AGENT", work, proof);

        Map<String, Object> row = store.agentTask("run-agent-task").orElseThrow();
        assertThat(row).containsEntry("sender", "DELEGATED_AGENT").containsEntry("model", "gpt-6-luna")
                .containsEntry("final_answer", "Revision 3.").containsEntry("stop_reason", "ANSWERED");
        JsonNode calls = json.readTree((String) row.get("tool_calls"));
        assertThat(calls.get(0).path("tool").asText()).isEqualTo("readDocument");
        assertThat(calls.get(0).path("answer").path("controls").path("D").asText()).isEqualTo("DELIVERED");
        JsonNode stored = json.readTree((String) row.get("proof"));
        assertThat(stored.path("controls").path("D").path("firstStopStep").asInt()).isEqualTo(1);
        assertThat(stored.path("mustNotLeave").get(0).asText()).isEqualTo("HX-310");
        assertThat(store.agentTask("run-without-task")).isEmpty();
    }

    @Test
    void theSummaryShowsEveryStepWithItsToolTheControlsOutcomesDsDecisionAndTheCost() throws Exception {
        store.start(new RunStore.RunStart("run-agent-summary", "T3", 1, "E-0042", "kim", null, "org", "tenant",
                "10.0.0.1", "laptop", AT, null, null, "{}", "b".repeat(64)));
        String scriptedRequest = UUID.randomUUID().toString();
        String agentRequest = UUID.randomUUID().toString();
        for (ControlEndpoints.Control control : ControlEndpoints.Control.values()) {
            store.armResult("run-agent-summary", 1, control, "EXPORT", outcome(scriptedRequest,
                    "/api/projects/HX-310/exports?items=40", "DELIVERED", 40));
            boolean refused = control == ControlEndpoints.Control.D || control == ControlEndpoints.Control.C2;
            store.armResult("run-agent-summary", 2, control, "EXPORT", outcome(UUID.randomUUID().toString(),
                    "/api/projects/GB-500/exports?items=400", refused ? "REFUSED" : "DELIVERED", refused ? 0 : 400));
        }
        jdbc.update("insert into run_decision (request_id, run_id, step_no, final_action, risk_score, model_calls, "
                + "total_tokens, applied, records, events) values (?, 'run-agent-summary', 2, 'BLOCK', 0.92, 1, "
                + "5100, 'BEFORE_RESPONSE', '[]'::jsonb, '[]'::jsonb)", UUID.fromString(agentRequest));
        store.cost("run-agent-summary", null, agentRequest, json.readTree(
                "{\"kind\":\"CHAT\",\"model\":\"gpt-6-luna\",\"promptTokens\":5000,\"completionTokens\":100,"
                        + "\"totalTokens\":5100}"));
        AgentWork.Answer answer = new AgentWork.Answer(2, "/api/projects/GB-500/exports?items=400", 403, "REFUSED",
                "ZERO_TRUST_BLOCK", "{}", Map.of("D", "REFUSED"), Map.of("D", 0), Map.of());
        AgentWork.Transcript work = new AgentWork.Transcript("gpt-6-luna", "prompt", "Export GB-500",
                List.of(new AgentWork.ToolCall(1, "exportDocuments", Map.of("projectKey", "GB-500", "items", 400), AT,
                        true, answer, "HTTP 403\n{}")), "It was refused.", "ANSWERED", null,
                Map.of("totalTokens", 900), AT, AT.plusSeconds(20));
        store.agentTask("run-agent-summary", "DELEGATED_AGENT", work, new AgentTaskProof.Proof(true, null,
                "It was refused.", "ANSWERED", true, List.of("GB-500"), null, 1, 1, 1,
                Map.of("D", new AgentTaskProof.Control(0, 0, 0, 0, 2, "REFUSED")), Map.of("totalTokens", 900)));

        JsonNode summary = json.valueToTree(store.agentTaskSummary("run-agent-summary").orElseThrow());

        assertThat(summary.path("stopReason").asText()).isEqualTo("ANSWERED");
        assertThat(summary.path("proof").path("controls").path("D").path("firstStopOutcome").asText())
                .isEqualTo("REFUSED");
        JsonNode steps = summary.path("steps");
        assertThat(steps).hasSize(2);
        assertThat(steps.get(0).path("sentBy").asText()).isEqualTo("SCRIPT");
        assertThat(steps.get(0).path("outcomes").path("A").path("deliveredItems").asInt()).isEqualTo(40);
        assertThat(steps.get(1).path("sentBy").asText()).isEqualTo("AGENT_WORK");
        assertThat(steps.get(1).path("tool").path("tool").asText()).isEqualTo("exportDocuments");
        assertThat(steps.get(1).path("tool").path("arguments").path("projectKey").asText()).isEqualTo("GB-500");
        assertThat(steps.get(1).path("outcomes").path("A").path("outcome").asText()).isEqualTo("DELIVERED");
        assertThat(steps.get(1).path("outcomes").path("D").path("outcome").asText()).isEqualTo("REFUSED");
        assertThat(steps.get(1).path("decision").path("final_action").asText()).isEqualTo("BLOCK");
        assertThat(summary.path("cost").path("agent").path("totalTokens").asInt()).isEqualTo(900);
        assertThat(summary.path("cost").path("decisions").get(0).path("model").asText()).isEqualTo("gpt-6-luna");
        assertThat(summary.path("cost").path("decisions").get(0).path("total_tokens").asLong()).isEqualTo(5100);
        assertThat(store.agentTaskSummary("run-without-task")).isEmpty();
    }

    private static ControlSession.StepOutcome outcome(String requestId, String path, String outcome, int items) {
        return new ControlSession.StepOutcome(requestId, "POST", path, AT, "DELIVERED".equals(outcome) ? 200 : 403,
                outcome, items, null, null, null, 30, AT, null);
    }
}
