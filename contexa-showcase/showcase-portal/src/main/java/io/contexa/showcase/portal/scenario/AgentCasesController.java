package io.contexa.showcase.portal.scenario;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator;
import io.contexa.showcase.portal.orchestrator.RunStore;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * docs/agent A7-3: what the visitor's business agent group reads of an agent case (화면설계 4절 AD-1, AD-3): the work
 * the employee gave the agent and its delegation as the case defines them, the legitimate case of the same delegated work
 * (the normal pair), and the latest operator recording of each, which the group shows when the visitor has no run of
 * their own; and an agent case run's work with its confirmation (AD-2 to AD-4).
 */
@RestController
public class AgentCasesController {

    /** docs/agent DD-26: the legitimate case of the same delegated work, within the delegation period. */
    static final Map<String, String> NORMAL_PAIRS = Map.of("T5", "N1");
    private static final Pattern KEY = Pattern.compile("[NT]\\d{1,2}");
    private static final Pattern RUN_ID = Pattern.compile("run-[0-9a-f]{12}");

    private final AgentTaskCatalog agentTasks;
    private final ObjectProvider<RunStore> runs;
    private final ObjectMapper json;

    public AgentCasesController(AgentTaskCatalog agentTasks, ObjectProvider<RunStore> runs, ObjectMapper json) {
        this.agentTasks = agentTasks;
        this.runs = runs;
        this.json = json;
    }

    /**
     * The delegation as the case records it; its times are minutes from the run's company time.
     *
     * @param validFromMinutes  when it starts, e.g. -10080 (seven days before)
     * @param validUntilMinutes when it ends, e.g. -120 (two hours before the work); null for no end
     */
    public record Delegation(String project, String purpose, Map<String, String> summary, List<String> operations,
                             List<String> resources, Long validFromMinutes, Long validUntilMinutes, String status,
                             boolean approvalRequired) {
    }

    /** An operator's recording of a case. */
    public record Recorded(String runId, Instant startedAt) {
    }

    /**
     * @param sender      who sends the agent's requests (DELEGATED_AGENT, ...)
     * @param instruction what the employee asked the agent, by language
     * @param normalPair  the legitimate case of the same delegated work; null when none
     */
    public record AgentCaseView(String key, int version, Map<String, String> title, String protagonist,
                                String agentName, Map<String, String> agentTitle, String sender,
                                Map<String, String> instruction, Delegation delegation, String classification,
                                String normalPair, Recorded recorded, Recorded normalRecorded) {
    }

    @GetMapping("/api/agent-cases/{key}")
    public ResponseEntity<AgentCaseView> agentCase(@PathVariable("key") String key) {
        if (!KEY.matcher(key).matches()) {
            return ResponseEntity.badRequest().build();
        }
        return agentTasks.find(key).map(task -> {
            String pair = NORMAL_PAIRS.get(key);
            ScenarioDefinition.Fact fact = task.facts().stream().filter(found -> "DELEGATION".equals(found.kind())
                    && found.delegated() != null).findFirst().orElse(null);
            Delegation delegation = fact == null ? null : new Delegation(fact.project(), fact.purpose(),
                    fact.delegated().summary(), fact.delegated().operations(), fact.delegated().resources(),
                    fact.validFromOffset() == null ? null : fact.validFromOffset().toMinutes(),
                    fact.validUntilOffset() == null ? null : fact.validUntilOffset().toMinutes(), fact.status(),
                    fact.delegated().approvalRequired());
            return ResponseEntity.ok(new AgentCaseView(task.key(), task.version(), task.title(), task.protagonist(),
                    task.agent().name(), task.agent().title(), task.task().sender().name(), task.task().instruction(),
                    delegation, task.oracle().classification(), pair, recorded(task),
                    pair == null ? null : agentTasks.find(pair).map(this::recorded).orElse(null)));
        }).orElseGet(() -> ResponseEntity.notFound().build());
    }

    /** An agent case run's work: what was asked, every step with its tool and the controls' outcomes, the confirmation. */
    @GetMapping("/api/runs/{runId}/agent")
    public ResponseEntity<Map<String, Object>> agentRun(@PathVariable("runId") String runId) {
        RunStore store = runs.getIfAvailable();
        if (!RUN_ID.matcher(runId).matches() || store == null) {
            return ResponseEntity.notFound().build();
        }
        return store.agentTaskSummary(runId).map(summary -> {
            Map<String, Object> view = new LinkedHashMap<>(summary);
            view.remove("systemPrompt");
            return ResponseEntity.ok(view);
        }).orElseGet(() -> ResponseEntity.notFound().build());
    }

    private Recorded recorded(ScenarioDefinition task) {
        RunStore store = runs.getIfAvailable();
        if (store == null) {
            return null;
        }
        return store.latestRecordedAgentRun(RunOrchestrator.definitionSha256(json, task))
                .map(row -> new Recorded((String) row.get("run_id"), instant(row.get("started_at"))))
                .orElse(null);
    }

    private static Instant instant(Object value) {
        if (value instanceof Timestamp timestamp) {
            return timestamp.toInstant();
        }
        if (value instanceof OffsetDateTime time) {
            return time.toInstant();
        }
        return value instanceof Instant instant ? instant : null;
    }
}
