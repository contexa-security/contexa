package io.contexa.showcase.portal.reactivity;

import io.contexa.showcase.portal.benchmark.BenchmarkService;
import io.contexa.showcase.portal.benchmark.BenchmarkView;
import io.contexa.showcase.portal.benchmark.DecisionQuality;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * W6-1 (P6-CHANGE-2, plan 8.6, metric R2): the invariance check. Repeating a case gives new run isolation ids, session
 * id, user id string, request ids and server clock by construction, so the repetitions of one case in one measurement
 * are its variants (P0-CHANGE-18): their prompts may differ only in Subject, and their decisions not at all. The first
 * step is compared as the variant; later steps also depend on the earlier steps' decisions and are counted apart (the
 * prototype is prompt-audit/w06/invariance_cases.py). The decisions use the R1 definition of the decision quality.
 */
public final class InvarianceEvaluator {

    private final DeliveryEvaluator delivery;

    public InvarianceEvaluator(DeliveryEvaluator delivery) {
        this.delivery = delivery;
    }

    /** One step of a repetition: its request, final action and sealed facts (null without a seal). */
    public record Step(int stepNo, String requestId, String finalAction, PromptFacts facts) {
    }

    /** One repetition of a case with its steps. */
    public record Run(String runId, List<Step> steps) {
    }

    /** One compared pair of a case's first repetition and another, at one step. */
    public record Pair(String caseKey, String baseRunId, String variantRunId, int stepNo,
                       DeliveryEvaluator.Delivery delivery) {
    }

    /**
     * The measurement: first-step pairs whose facts changed only as expected, later-step pairs the same way, the
     * facts that changed and how often, the steps decided more than once with one action, and the pairs not compared
     * for want of a seal.
     */
    public record Invariance(BenchmarkView.Rate firstStepFacts, BenchmarkView.Rate laterStepFacts,
                             Map<String, Integer> changedFacts, BenchmarkView.Rate decisions, int notSealed,
                             List<Pair> pairs) {
    }

    /** The repetitions of each case of one measurement, the first repetition first. */
    public Invariance evaluate(Map<String, List<Run>> repetitions) {
        List<Pair> pairs = new ArrayList<>();
        List<DecisionQuality.Decision> decisions = new ArrayList<>();
        Map<String, Integer> changed = new TreeMap<>();
        int notSealed = 0;
        for (Map.Entry<String, List<Run>> entry : repetitions.entrySet()) {
            List<Run> runs = entry.getValue();
            for (Run run : runs) {
                for (Step step : run.steps()) {
                    decisions.add(new DecisionQuality.Decision(step.requestId(), entry.getKey(), step.stepNo(),
                            step.finalAction(), null, false));
                }
            }
            if (runs.size() < 2) {
                continue;
            }
            Run base = runs.get(0);
            for (Run other : runs.subList(1, runs.size())) {
                for (Step step : base.steps()) {
                    Step variant = other.steps().stream().filter(candidate -> candidate.stepNo() == step.stepNo())
                            .findFirst().orElse(null);
                    if (variant == null) {
                        continue;
                    }
                    if (step.facts() == null || variant.facts() == null) {
                        notSealed++;
                        continue;
                    }
                    DeliveryEvaluator.Delivery result = delivery.compare(step.facts(), variant.facts(),
                            DeliveryEvaluator.INVARIANT);
                    result.unexpected().forEach(name -> changed.merge(name, 1, Integer::sum));
                    pairs.add(new Pair(entry.getKey(), base.runId(), other.runId(), step.stepNo(), result));
                }
            }
        }
        long first = pairs.stream().filter(pair -> pair.stepNo() == 1).count();
        long firstPassed = pairs.stream().filter(pair -> pair.stepNo() == 1 && pair.delivery().passed()).count();
        long later = pairs.size() - first;
        long laterPassed = pairs.stream().filter(pair -> pair.stepNo() != 1 && pair.delivery().passed()).count();
        return new Invariance(BenchmarkService.rate(firstPassed, first), BenchmarkService.rate(laterPassed, later),
                Collections.unmodifiableMap(changed), DecisionQuality.of(decisions, Map.of()).consistency(), notSealed,
                List.copyOf(pairs));
    }
}
