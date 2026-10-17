package io.contexa.showcase.portal.reactivity;

import io.contexa.showcase.portal.benchmark.BenchmarkService;
import io.contexa.showcase.portal.benchmark.BenchmarkView;
import io.contexa.showcase.portal.benchmark.DecisionQuality;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * W7-13 (docs/showcase/화면설계-프롬프트신뢰-보강안.md 3.5, 5): the benchmark's prompt quality tab, each figure with its
 * counts and Wilson 95% interval: the harness metrics of a batch and a measurement's repetitions (W6-1, plan 8.4 to
 * 8.7) and the decision quality of the measurement (W6-2). A figure is null when its source holds nothing to count.
 *
 * @param measuredAt when the data was complete: the latest of the protocol's end and the batches' last records
 * @param batch      the one batch every harness figure comes from; null when they come from different batches
 * @param batches    N-PQ-1: the batch each harness figure comes from (delivery, reaction, injection)
 * @param delivery   lab runs whose changed condition reached only its expected lines (C4)
 * @param injection  injection runs whose facts or decision the injected text changed, and the rate of those it
 *                   left as the base run's
 * @param accuracy   decisions with a correct action on cases with a ground truth (A3)
 * @param consistency repeated case steps decided with one action (R1)
 * @param reasonMatch decisions whose reason codes matched their facts (C3)
 * @param comparison U6-4: A1 and A2 of the earlier measurement and of this one; null without an earlier one
 * @param raw        U6-5: the figures' sources with their per-run results, as published; the visitor API gives it
 *                   only to the raw data download (raw=true), never to the screen's read
 */
public record PromptQualityView(Instant measuredAt, String setting, String batch, Batches batches, String protocol,
                                BenchmarkView.Rate delivery, Reaction reaction, Invariance invariance,
                                Injection injection, BenchmarkView.Rate accuracy,
                                BenchmarkView.Rate consistency, BenchmarkView.Rate reasonMatch, Comparison comparison,
                                Raw raw) {

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

    /**
     * N-PQ-1: the batch of each harness figure. The plan measures delivery, reaction and injection in batches of their
     * own (8.4, 8.5, 8.7), so a publication names each; a figure without a batch of its own takes the one batch given.
     */
    public record Batches(String delivery, String reaction, String injection) {

        /** Each figure's own batch, or the one batch given for a figure without one (null when neither is given). */
        public static Batches of(String batch, String delivery, String reaction, String injection) {
            return new Batches(named(delivery, batch), named(reaction, batch), named(injection, batch));
        }

        /** The first figure without a batch, or null when each has one. */
        public String missing() {
            return delivery == null ? "delivery" : reaction == null ? "reaction" : injection == null ? "injection"
                    : null;
        }

        /** The one batch of all three figures, or null when they differ. */
        public String single() {
            return delivery != null && delivery.equals(reaction) && delivery.equals(injection) ? delivery : null;
        }

        /** The figures and their batches, in the order the tab shows them. */
        public Map<String, String> byMetric() {
            Map<String, String> metrics = new LinkedHashMap<>();
            metrics.put("delivery", delivery);
            metrics.put("reaction", reaction);
            metrics.put("injection", injection);
            return metrics;
        }

        private static String named(String value, String fallback) {
            return value == null || value.isBlank() ? fallback : value;
        }
    }

    /**
     * U6-4: the run-level reaction of the earlier measurement and of this one, counted by one definition
     * (RunLevelReaction, as prompt-audit/p0/run_level_reaction.py and the preregistration's A1 and A2): attack runs
     * reacted (A1) and normal runs asked to verify or more (A2), each side with the bundle its runs ran.
     */
    public record Comparison(String baselineProtocol, String baselineBundle, String bundle,
                             BenchmarkView.Rate attackBefore, BenchmarkView.Rate attackNow,
                             BenchmarkView.Rate normalBefore, BenchmarkView.Rate normalNow) {

        public static Comparison of(String baselineProtocol, String baselineBundle, String bundle,
                                    RunLevelReaction.Counts before, RunLevelReaction.Counts now) {
            return new Comparison(baselineProtocol, baselineBundle, bundle,
                    rate(before.attackReacted(), before.attackRuns()), rate(now.attackReacted(), now.attackRuns()),
                    rate(before.normalReacted(), before.normalRuns()), rate(now.normalReacted(), now.normalRuns()));
        }

        /** A side with no run of the class has no rate (null), never 0 of 0. */
        private static BenchmarkView.Rate rate(long hits, long total) {
            return total == 0 ? null : BenchmarkService.rate(hits, total);
        }
    }

    /**
     * U6-5: the sources of the harness figures as published, with their per-run results: the delivery batch's
     * delivery, the reaction batch's reaction, the injection batch's injection and the protocol's invariance.
     */
    public record Raw(ReactivityService.BatchDelivery delivery, ReactionEvaluator.Summary reaction,
                      InjectionEvaluator.Summary injection, InvarianceEvaluator.Invariance invariance) {
    }

    /** One batch for every harness figure (the call before N-PQ-1), invariance from the same report. */
    public static PromptQualityView of(Instant measuredAt, String setting, String batch, String protocol,
                                       ReactivityService.Report report, DecisionQuality quality) {
        return of(measuredAt, setting, new Batches(batch, batch, batch), protocol, report, report, report, report,
                quality, null);
    }

    /**
     * N-PQ-1: each harness figure from the report of its own batch, invariance from the repetitions of the protocol
     * (report(null, protocol)), the decision quality of the protocol, the U6-4 comparison (null without an earlier
     * measurement) and the U6-5 raw data of those reports.
     */
    public static PromptQualityView of(Instant measuredAt, String setting, Batches batches, String protocol,
                                       ReactivityService.Report delivery, ReactivityService.Report reaction,
                                       ReactivityService.Report injection, ReactivityService.Report repetitions,
                                       DecisionQuality quality, Comparison comparison) {
        ReactionEvaluator.Summary reacted = reaction.reaction();
        InvarianceEvaluator.Invariance invariant = repetitions.invariance();
        return new PromptQualityView(measuredAt, setting, batches.single(), batches, protocol,
                delivery.delivery() == null ? null : delivery.delivery().delivered(),
                reacted == null ? null : new Reaction(reacted.direction(), reacted.minimumKept(),
                        reacted.consistency()),
                invariant == null ? null : new Invariance(invariant.firstStepFacts(), invariant.decisions(),
                        invariant.decisions().total() - invariant.decisions().hits()),
                injection.injection() == null ? null : Injection.of(injection.injection().unchanged()),
                quality.accuracy(), quality.consistency(), quality.reasonMatch(), comparison,
                new Raw(delivery.delivery(), reacted, injection.injection(), invariant));
    }
}
