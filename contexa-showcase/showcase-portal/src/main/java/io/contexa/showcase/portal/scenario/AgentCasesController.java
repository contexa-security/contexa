package io.contexa.showcase.portal.scenario;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator;
import io.contexa.showcase.portal.orchestrator.RunStore;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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
    static final Map<String, String> NORMAL_PAIRS = Map.of("T5", "N1", "M19A", "M19N");
    /** A case key as the catalog writes them (N1, T5, M14A, VN1C): capital letters and digits, at most five. */
    private static final Pattern KEY = Pattern.compile("[A-Z][A-Z0-9]{0,4}");
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
     * @param maxItemsPerRequest the quantity limit the delegation states per request; null when it states none
     */
    public record Delegation(String project, String purpose, Map<String, String> summary, List<String> operations,
                             List<String> resources, Long validFromMinutes, Long validUntilMinutes, String status,
                             boolean approvalRequired, Integer maxItemsPerRequest) {
    }

    /**
     * An operator's recording of a case.
     *
     * @param runs         how many recordings the case's definition has (docs/agent Agent중심-화면 AS-5)
     * @param sameAsLatest how many of them ended as this one did at control D
     */
    public record Recorded(String runId, Instant startedAt, int runs, int sameAsLatest) {
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

    /** The case as it is. */
    public ResponseEntity<AgentCaseView> agentCase(String key) {
        return agentCase(key, null, null, null);
    }

    /**
     * The case, with the visitor's choice of the delegation of the editable case applied when one is given (docs/agent
     * Agent중심-화면 AS-12): the delegation a visitor sees before sending is the one the run will execute. A value
     * outside the fixed lists, or a choice on any other case, is refused. Nothing is stored.
     */
    @GetMapping("/api/agent-cases/{key}")
    public ResponseEntity<AgentCaseView> agentCase(@PathVariable("key") String key,
                                                   @RequestParam(name = "quantity", required = false) Integer quantity,
                                                   @RequestParam(name = "period", required = false) String period,
                                                   @RequestParam(name = "operations", required = false) String operations) {
        if (!KEY.matcher(key).matches()) {
            return ResponseEntity.badRequest().build();
        }
        DelegationChoice choice;
        try {
            choice = new DelegationChoice(quantity, period, operations);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        }
        Optional<ScenarioDefinition> found = agentTasks.find(key);
        if (found.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        try {
            return ResponseEntity.ok(viewOf(choice.applyTo(found.get()), true));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        }
    }

    /**
     * An agent case as the visitor reads it. The agent menu (docs/agent Agent중심-화면 AC-4a) reads its cases the same way,
     * without the operator recordings of the case, which it has stored runs of its own for.
     */
    public AgentCaseView viewOf(ScenarioDefinition task, boolean withRecordings) {
        String pair = NORMAL_PAIRS.get(task.key());
        Delegation delegation = delegationOf(task);
        return new AgentCaseView(task.key(), task.version(), task.title(), task.protagonist(),
                task.agent().name(), task.agent().title(), task.task().sender().name(), task.task().instruction(),
                delegation, task.oracle().classification(), pair, withRecordings ? recorded(task) : null,
                withRecordings && pair != null ? agentTasks.find(pair).map(this::recorded).orElse(null) : null);
    }

    /**
     * The delegation a definition states: the case's own, or a visitor's copy with its one change (docs/agent AS-12);
     * null for a definition with none.
     */
    public static Delegation delegationOf(ScenarioDefinition task) {
        ScenarioDefinition.Fact fact = task.facts().stream().filter(found -> "DELEGATION".equals(found.kind())
                && found.delegated() != null).findFirst().orElse(null);
        if (fact == null) {
            return null;
        }
        // A delegation the administrator withdraws (or an agent the administrator stops) before the work is told revoked.
        boolean withdrawn = task.task() != null && task.task().adminActionsOn(task.task().sender()).stream()
                .anyMatch(action -> action.afterToolCalls() == 0);
        return new Delegation(fact.project(), fact.purpose(),
                fact.delegated().summary(), fact.delegated().operations(), fact.delegated().resources(),
                fact.validFromOffset() == null ? null : fact.validFromOffset().toMinutes(),
                fact.validUntilOffset() == null ? null : fact.validUntilOffset().toMinutes(),
                withdrawn ? "REVOKED" : fact.status(), fact.delegated().approvalRequired(),
                fact.delegated().maxItemsPerRequest());
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
            // docs/agent AS-12: the delegation this run executed (a visitor's copy differs from the case's own)
            Optional<ScenarioDefinition> executed = store.scenarioDefinition(runId);
            executed.map(AgentCasesController::delegationOf).ifPresent(delegation -> view.put("delegation", delegation));
            return ResponseEntity.ok(withBurst(view, executed, json));
        }).orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * docs/agent Agent중심-화면 AS-13: the run of a burst carries the counts the portal makes of it, counted from the
     * run's own steps the way the stored measurements are (what was delivered, refused, analysed, the model calls, the
     * step control D first stopped at), so the screen reads a visitor's burst as it reads the stored ones.
     */
    static Map<String, Object> withBurst(Map<String, Object> view, Optional<ScenarioDefinition> executed,
                                         ObjectMapper json) {
        if (executed.isPresent() && BurstChoice.isBurst(executed.get())) {
            view.put("burst", AgentSnapshotsController.summary(json.valueToTree(view)));
        }
        return view;
    }

    private Recorded recorded(ScenarioDefinition task) {
        RunStore store = runs.getIfAvailable();
        if (store == null) {
            return null;
        }
        String sha = RunOrchestrator.definitionSha256(json, task);
        RunStore.RecordedStats stats = store.recordedAgentRunStats(sha);
        return store.latestRecordedAgentRun(sha)
                .map(row -> new Recorded((String) row.get("run_id"), instant(row.get("started_at")), stats.runs(),
                        stats.sameAsLatest()))
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
