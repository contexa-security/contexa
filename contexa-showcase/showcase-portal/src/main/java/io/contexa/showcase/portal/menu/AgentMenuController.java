package io.contexa.showcase.portal.menu;

import io.contexa.showcase.portal.orchestrator.RunStore;
import io.contexa.showcase.portal.scenario.AgentCasesController;
import io.contexa.showcase.portal.scenario.AgentTaskCatalog;
import io.contexa.showcase.portal.scenario.DelegationChoice;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * docs/agent Agent중심-화면 AC-4: the visitor's side of the agent menu: the table of cases and paths with the age of each
 * answer, and one answer: the case as the visitor reads it and the stored run that answers it. AC-4b: the editable case's
 * combinations carry a delegation choice, named by three query values of the fixed lists. Both are read from what the
 * daily job stored; no model is called and nothing is run for the visit. An answer is "stale" when it ran an older
 * definition of the case than the one in force or is older than {@link #STALE_AFTER}, and it is still shown, marked,
 * never replaced by an empty page.
 */
@RestController
@ConditionalOnProperty(prefix = "showcase.portal.controls", name = "d")
public class AgentMenuController {

    /** How old an answer may be before the menu marks it: the job runs daily, so a day and a half is a missed day. */
    public static final Duration STALE_AFTER = Duration.ofHours(36);

    public record CaseOption(String key, Map<String, String> title) {
    }

    /** @param choice the delegation choice of the editable case's combination; null for a case without one */
    public record Item(String caseKey, String path, DelegationChoice choice, Instant ranAt, boolean stale) {
    }

    /** @param delegationEdit the editable case and the values a visitor may choose; null while it is not packaged */
    public record Listing(List<CaseOption> cases, List<String> paths, List<Item> items,
                          Map<String, Object> delegationEdit) {
    }

    public record Answer(String caseKey, String path, DelegationChoice choice, Instant ranAt, boolean stale,
                         AgentCasesController.AgentCaseView caseView, Map<String, Object> run) {
    }

    private final AgentMenuStore store;
    private final AgentMenuJob job;
    private final AgentTaskCatalog catalog;
    private final AgentCasesController cases;
    private final RunStore runs;
    private final Clock clock;

    @Autowired
    public AgentMenuController(AgentMenuStore store, AgentMenuJob job, AgentTaskCatalog catalog,
                               AgentCasesController cases, RunStore runs) {
        this(store, job, catalog, cases, runs, Clock.systemUTC());
    }

    AgentMenuController(AgentMenuStore store, AgentMenuJob job, AgentTaskCatalog catalog,
                        AgentCasesController cases, RunStore runs, Clock clock) {
        this.store = store;
        this.job = job;
        this.catalog = catalog;
        this.cases = cases;
        this.runs = runs;
        this.clock = clock;
    }

    @GetMapping("/api/agent-menu")
    public Listing menu() {
        List<CaseOption> options = AgentMenu.CASES.stream()
                .map(key -> catalog.find(key).map(task -> new CaseOption(key, task.title())).orElse(null))
                .filter(option -> option != null).toList();
        List<Item> items = store.all().stream()
                .filter(entry -> AgentMenu.has(entry.caseKey(), entry.path(), DelegationChoice.parse(entry.choiceKey())))
                .map(entry -> new Item(entry.caseKey(), entry.path(), DelegationChoice.parse(entry.choiceKey()),
                        entry.ranAt(), stale(entry))).toList();
        Map<String, Object> edit = catalog.find(DelegationChoice.EDITABLE_CASE)
                .map(task -> DelegationChoice.describe(DelegationChoice.EDITABLE_CASE, task.title())).orElse(null);
        return new Listing(options, AgentMenu.PATHS, items, edit);
    }

    /** The answer of a combination without a choice. */
    public ResponseEntity<Answer> answer(String caseKey, String path) {
        return answer(caseKey, path, null, null, null);
    }

    @GetMapping("/api/agent-menu/{caseKey}/{path}")
    public ResponseEntity<Answer> answer(@PathVariable("caseKey") String caseKey, @PathVariable("path") String path,
                                         @RequestParam(name = "quantity", required = false) Integer quantity,
                                         @RequestParam(name = "period", required = false) String period,
                                         @RequestParam(name = "operations", required = false) String operations) {
        DelegationChoice choice;
        try {
            choice = new DelegationChoice(quantity, period, operations);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        }
        DelegationChoice named = choice.isEmpty() ? null : choice;
        if (!AgentMenu.has(caseKey, path, named)) {
            return ResponseEntity.badRequest().build();
        }
        Optional<AgentMenuStore.Entry> entry = store.find(caseKey, path, named == null ? "" : named.key());
        if (entry.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        Optional<Map<String, Object>> run = runs.agentTaskSummary(entry.get().runId());
        if (run.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        Map<String, Object> view = new LinkedHashMap<>(run.get());
        view.remove("systemPrompt");
        return catalog.find(caseKey).map(task -> ResponseEntity.ok(new Answer(caseKey, path, named,
                        entry.get().ranAt(), stale(entry.get()), cases.viewOf(named == null ? task : named.applyTo(task), false),
                        view)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    private boolean stale(AgentMenuStore.Entry entry) {
        boolean old = Duration.between(entry.ranAt(), clock.instant()).compareTo(STALE_AFTER) > 0;
        DelegationChoice choice = DelegationChoice.parse(entry.choiceKey());
        return old || !entry.definitionSha256().equals(job.shaOf(new AgentMenu.Combo(entry.caseKey(), entry.path(), choice)));
    }
}
