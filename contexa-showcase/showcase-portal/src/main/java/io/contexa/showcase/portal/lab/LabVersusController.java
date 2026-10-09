package io.contexa.showcase.portal.lab;

import io.contexa.showcase.portal.anatomy.AnatomyStore;
import io.contexa.showcase.portal.anatomy.DecisionAnatomy;
import io.contexa.showcase.portal.anatomy.InputComparison;
import io.contexa.showcase.portal.replay.ReplayView;
import io.contexa.showcase.portal.replay.ReplayViews;
import io.contexa.showcase.portal.scoring.RunScores;
import io.contexa.showcase.portal.scoring.RunScores.RunScore;
import io.contexa.showcase.portal.scoring.Scoring.CaseScore;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * The lab's "previous run against this run" (lab-3, 7.6 of docs/showcase/화면설계서-v2-구현계획.md): every approach's
 * business result in both runs, Contexa's first decision and the items that left, which approaches changed, and what
 * the engine received differently on the first request. The server compares; the screen only shows the answer.
 */
@RestController
public class LabVersusController {

    /**
     * One run as the comparison reads it.
     *
     * @param business     every approach's business result, by control (NOT_SCORED for a case without a ground truth)
     * @param outcomes     how every approach answered, by control: the strongest answer over the run's requests
     *                     (stopped, cut or broken, then held, then delivered), so a composed case without a ground truth
     *                     still shows what each approach did
     * @param engineAction the first decision Contexa made in the run; null when it made none
     * @param exposedItems the items that left through Contexa over the whole run
     */
    public record Side(String runId, String scenarioKey, Map<String, String> business, Map<String, String> outcomes,
                       String engineAction, long exposedItems) {
    }

    /**
     * @param changedControls the approaches whose answer differs, in the controls' order
     * @param contexaChanged  whether Contexa's answer or first decision differs
     * @param inputs          what the engine received differently on the first request; empty when either run has
     *                        no stored decision for it
     * @param changedConditions the lab conditions whose value differs between the two runs, as the lab stored them
     *                          (lab-3 headline: "only the approval changed"); null when either run is not a lab run
     */
    public record Versus(Side before, Side now, List<String> changedControls, boolean contexaChanged,
                         List<InputComparison.Change> inputs, List<String> changedConditions) {
    }

    /** The answers from the strongest to the weakest; a run's answer is the strongest over its requests. */
    static final List<String> STRENGTH = List.of("STOPPED", "CUT", "BROKEN", "HELD", "UNRESOLVED", "DELIVERED");

    private final RunScores scores;
    private final AnatomyStore anatomies;
    private final ReplayViews steps;
    private final LabStore lab;

    public LabVersusController(RunScores scores, AnatomyStore anatomies, ReplayViews steps, LabStore lab) {
        this.scores = scores;
        this.anatomies = anatomies;
        this.steps = steps;
        this.lab = lab;
    }

    @GetMapping("/api/runs/{runId}/versus")
    public ResponseEntity<Versus> versus(@PathVariable("runId") String runId,
                                         @RequestParam("against") String against) {
        Optional<RunScore> now = scores.score(runId);
        Optional<RunScore> before = scores.score(against);
        if (now.isEmpty() || before.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        Optional<DecisionAnatomy> nowAnatomy = anatomies.anatomy(runId, 1);
        Optional<DecisionAnatomy> beforeAnatomy = anatomies.anatomy(against, 1);
        List<InputComparison.Change> inputs = nowAnatomy.isPresent() && beforeAnatomy.isPresent()
                ? InputComparison.changes(beforeAnatomy.get(), nowAnatomy.get()) : List.of();
        Optional<Map<String, Object>> nowConditions = lab.conditions(runId);
        Optional<Map<String, Object>> beforeConditions = lab.conditions(against);
        List<String> conditions = nowConditions.isPresent() && beforeConditions.isPresent()
                ? changedConditions(beforeConditions.get(), nowConditions.get()) : null;
        return ResponseEntity.ok(compare(side(before.get(), outcomes(against, before.get())),
                side(now.get(), outcomes(runId, now.get())), inputs, conditions));
    }

    /** The conditions whose stored value differs, in the before run's order and then any the later run adds. */
    static List<String> changedConditions(Map<String, Object> before, Map<String, Object> now) {
        Set<String> names = new LinkedHashSet<>(before.keySet());
        names.addAll(now.keySet());
        List<String> changed = new ArrayList<>();
        for (String name : names) {
            if (!Objects.equals(before.get(name), now.get(name))) {
                changed.add(name);
            }
        }
        return List.copyOf(changed);
    }

    /** Every approach's strongest answer over the run's stored requests. */
    private Map<String, String> outcomes(String runId, RunScore score) {
        List<List<ReplayView.Layer>> answers = new ArrayList<>();
        for (int step = 1; step <= Math.max(1, score.executedSteps()); step++) {
            steps.storedStep(runId, step).ifPresent(result -> answers.add(result.layers()));
        }
        return strongest(answers);
    }

    static Map<String, String> strongest(List<List<ReplayView.Layer>> answers) {
        Map<String, String> outcomes = new LinkedHashMap<>();
        for (List<ReplayView.Layer> layers : answers) {
            for (ReplayView.Layer layer : layers) {
                String known = outcomes.get(layer.control());
                if (known == null || rank(layer.outcome()) < rank(known)) {
                    outcomes.put(layer.control(), layer.outcome());
                }
            }
        }
        return outcomes;
    }

    private static int rank(String outcome) {
        int index = STRENGTH.indexOf(outcome);
        return index < 0 ? STRENGTH.size() : index;
    }

    static Versus compare(Side before, Side now, List<InputComparison.Change> inputs, List<String> conditions) {
        List<String> changed = new ArrayList<>();
        for (String control : now.outcomes().keySet()) {
            if (!Objects.equals(before.outcomes().get(control), now.outcomes().get(control))) {
                changed.add(control);
            }
        }
        boolean contexaChanged = !Objects.equals(before.outcomes().get("D"), now.outcomes().get("D"))
                || !Objects.equals(before.engineAction(), now.engineAction());
        return new Versus(before, now, List.copyOf(changed), contexaChanged, inputs, conditions);
    }

    static Side side(RunScore score, Map<String, String> outcomes) {
        Map<String, String> business = new LinkedHashMap<>();
        score.business().forEach((control, result) -> business.put(control, result.result().name()));
        CaseScore engine = score.business().get("D");
        String action = score.verdicts().stream().map(verdict -> verdict.score().finalAction())
                .filter(Objects::nonNull).findFirst().orElse(null);
        return new Side(score.runId(), score.scenarioKey(), business, outcomes, action,
                engine == null ? 0 : engine.exposedItems());
    }
}
