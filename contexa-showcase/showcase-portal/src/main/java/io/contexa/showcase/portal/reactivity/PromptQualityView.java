package io.contexa.showcase.portal.reactivity;

import io.contexa.showcase.portal.benchmark.BenchmarkView;
import io.contexa.showcase.portal.benchmark.DecisionQuality;

import java.time.Instant;

/**
 * W7-13 (docs/showcase/화면설계-프롬프트신뢰-보강안.md 3.5, 5): the benchmark's prompt quality tab, each figure with its
 * counts and Wilson 95% interval: the harness metrics of a batch and a measurement's repetitions (W6-1, plan 8.4 to
 * 8.7) and the decision quality of the measurement (W6-2). A figure is null when its source holds nothing to count.
 *
 * @param measuredAt when the data was complete: the later of the protocol's end and the batch's last record
 * @param delivery   lab runs whose changed condition reached only its expected lines (C4)
 * @param injection  injection runs whose facts or decision the injected text changed, and the rate of those it
 *                   left as the base run's
 * @param accuracy   decisions with a correct action on cases with a ground truth (A3)
 * @param consistency repeated case steps decided with one action (R1)
 * @param reasonMatch decisions whose reason codes matched their facts (C3)
 */
public record PromptQualityView(Instant measuredAt, String setting, String batch, String protocol,
                                BenchmarkView.Rate delivery, Reaction reaction, Invariance invariance,
                                Injection injection, BenchmarkView.Rate accuracy,
                                BenchmarkView.Rate consistency, BenchmarkView.Rate reasonMatch) {

    /** The reaction check (A4): the direction, the minimum actions kept and the repeated variants' agreement. */
    public record Reaction(BenchmarkView.Rate direction, BenchmarkView.Rate minimumKept,
                           BenchmarkView.Rate consistency) {
    }

    /**
     * The invariance check (R2): first-step facts unchanged across repetitions, their decisions, and the repeated case
     * steps whose decisions differ, from the same counts as the decisions.
     */
    public record Invariance(BenchmarkView.Rate firstStepFacts, BenchmarkView.Rate decisions, long decisionChanges) {
    }

    /**
     * The injection check (C5): the injection runs whose facts or decision changed, and the rate of those whose facts
     * and decision stayed the base run's.
     */
    public record Injection(long changed, BenchmarkView.Rate unchanged) {

        static Injection of(BenchmarkView.Rate unchanged) {
            return new Injection(unchanged.total() - unchanged.hits(), unchanged);
        }
    }

    public static PromptQualityView of(Instant measuredAt, String setting, String batch, String protocol,
                                       ReactivityService.Report report, DecisionQuality quality) {
        ReactionEvaluator.Summary reacted = report.reaction();
        InvarianceEvaluator.Invariance invariant = report.invariance();
        return new PromptQualityView(measuredAt, setting, batch, protocol,
                report.delivery() == null ? null : report.delivery().delivered(),
                reacted == null ? null : new Reaction(reacted.direction(), reacted.minimumKept(),
                        reacted.consistency()),
                invariant == null ? null : new Invariance(invariant.firstStepFacts(), invariant.decisions(),
                        invariant.decisions().total() - invariant.decisions().hits()),
                report.injection() == null ? null : Injection.of(report.injection().unchanged()),
                quality.accuracy(), quality.consistency(), quality.reasonMatch());
    }
}
