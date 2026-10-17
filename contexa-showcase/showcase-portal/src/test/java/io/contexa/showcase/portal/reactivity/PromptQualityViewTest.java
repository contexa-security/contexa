package io.contexa.showcase.portal.reactivity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.benchmark.BenchmarkService;
import io.contexa.showcase.portal.benchmark.BenchmarkView;
import io.contexa.showcase.portal.benchmark.DecisionQuality;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W7-13 (docs/showcase/화면설계-프롬프트신뢰-보강안.md 3.5, 5): the benchmark's prompt quality tab takes each figure from
 * its source as counted, with its counts and Wilson interval: delivery, reaction and injection from the harness
 * batch, invariance from the measurement's repetitions (W6-1), and accuracy, consistency and reason match from the
 * measurement's decision quality (W6-2).
 */
class PromptQualityViewTest {

    private static final BenchmarkView.Rate DELIVERED = BenchmarkService.rate(10, 11);
    private static final BenchmarkView.Rate DIRECTION = BenchmarkService.rate(110, 116);
    private static final BenchmarkView.Rate MINIMUM_KEPT = BenchmarkService.rate(60, 60);
    private static final BenchmarkView.Rate REACTION_CONSISTENCY = BenchmarkService.rate(37, 40);
    private static final BenchmarkView.Rate FIRST_STEP = BenchmarkService.rate(25, 26);
    private static final BenchmarkView.Rate LATER_STEPS = BenchmarkService.rate(5, 9);
    private static final BenchmarkView.Rate DECISIONS = BenchmarkService.rate(12, 13);
    private static final BenchmarkView.Rate UNCHANGED = BenchmarkService.rate(5, 6);
    private static final BenchmarkView.Rate ACCURACY = BenchmarkService.rate(30, 39);
    private static final BenchmarkView.Rate CONSISTENCY = BenchmarkService.rate(11, 13);
    private static final BenchmarkView.Rate REASON_MATCH = BenchmarkService.rate(35, 36);
    /** N-PQ-1: a figure of another batch, which the view must not show. */
    private static final BenchmarkView.Rate OTHER = BenchmarkService.rate(93, 348);
    private static final Instant MEASURED = Instant.parse("2026-10-16T05:00:00Z");

    @Test
    void everyFigureIsTakenFromItsSourceAsCounted() {
        PromptQualityView view = PromptQualityView.of(MEASURED, "f".repeat(64), "w7-2", "proto-1", report(),
                new DecisionQuality(ACCURACY, CONSISTENCY, REASON_MATCH, 0));

        assertThat(view.measuredAt()).isEqualTo(MEASURED);
        assertThat(view.batch()).isEqualTo("w7-2");
        assertThat(view.protocol()).isEqualTo("proto-1");
        assertThat(view.delivery()).isEqualTo(DELIVERED);
        assertThat(view.reaction()).isEqualTo(new PromptQualityView.Reaction(DIRECTION, MINIMUM_KEPT,
                REACTION_CONSISTENCY));
        assertThat(view.invariance()).as("one repeated step decided two ways")
                .isEqualTo(new PromptQualityView.Invariance(FIRST_STEP, DECISIONS, 1));
        assertThat(view.injection()).as("one injection run changed")
                .isEqualTo(new PromptQualityView.Injection(1, UNCHANGED));
        assertThat(view.accuracy()).isEqualTo(ACCURACY);
        assertThat(view.consistency()).isEqualTo(CONSISTENCY);
        assertThat(view.reasonMatch()).isEqualTo(REASON_MATCH);
    }

    @Test
    void aSourceThatWasNotCountedLeavesItsFigureEmpty() {
        PromptQualityView view = PromptQualityView.of(MEASURED, "f".repeat(64), "w7-2", "proto-1",
                new ReactivityService.Report("w7-2", "proto-1", null, null, null, null),
                new DecisionQuality(ACCURACY, CONSISTENCY, REASON_MATCH, 0));

        assertThat(view.delivery()).isNull();
        assertThat(view.reaction()).isNull();
        assertThat(view.invariance()).isNull();
        assertThat(view.injection()).isNull();
        assertThat(view.accuracy()).isEqualTo(ACCURACY);
    }

    @Test
    void theViewHasTheContractsFields() {
        JsonNode view = new ObjectMapper().findAndRegisterModules().valueToTree(PromptQualityView.of(MEASURED,
                "f".repeat(64), "w7-2", "proto-1", report(), new DecisionQuality(ACCURACY, CONSISTENCY, REASON_MATCH,
                        0)));

        assertThat(names(view)).containsExactlyInAnyOrder("measuredAt", "setting", "batch", "batches", "protocol",
                "delivery", "reaction", "invariance", "injection", "accuracy", "consistency", "reasonMatch",
                "comparison", "raw");
        assertThat(names(view.path("batches"))).as("N-PQ-1").containsExactlyInAnyOrder("delivery", "reaction",
                "injection");
        assertThat(names(view.path("raw"))).as("U6-5").containsExactlyInAnyOrder("delivery", "reaction", "injection",
                "invariance");
        assertThat(names(view.path("reaction"))).containsExactlyInAnyOrder("direction", "minimumKept",
                "consistency");
        assertThat(names(view.path("invariance"))).containsExactlyInAnyOrder("firstStepFacts", "decisions",
                "decisionChanges");
        assertThat(names(view.path("injection"))).containsExactlyInAnyOrder("changed", "unchanged");
        assertThat(names(view.path("injection").path("unchanged"))).containsExactlyInAnyOrder("hits", "total", "rate",
                "low", "high", "preliminary");
        assertThat(names(view.path("delivery"))).containsExactlyInAnyOrder("hits", "total", "rate", "low", "high",
                "preliminary");
    }

    @Test
    void eachHarnessFigureComesFromTheBatchItWasMeasuredIn() {
        // N-PQ-1: delivery, reaction and injection are measured in batches of their own (plan 8.4, 8.5, 8.7); the
        // reaction batch holds lab runs too, whose delivery is not the delivery measurement.
        PromptQualityView.Batches batches = PromptQualityView.Batches.of(null, "p8-delivery", "p8-reaction",
                "p8-injection");
        ReactivityService.Report delivery = part("p8-delivery", DELIVERED, null, null);
        ReactivityService.Report reaction = part("p8-reaction", OTHER, reacted(), null);
        ReactivityService.Report injection = part("p8-injection", OTHER, null, injected());
        PromptQualityView.Comparison comparison = new PromptQualityView.Comparison("proto-0", "v19", "v20", OTHER,
                DELIVERED, OTHER, DELIVERED);

        PromptQualityView view = PromptQualityView.of(MEASURED, "f".repeat(64), batches, "proto-1", delivery, reaction,
                injection, repetitions(), quality(), comparison);

        assertThat(view.delivery()).isEqualTo(DELIVERED);
        assertThat(view.reaction()).isEqualTo(new PromptQualityView.Reaction(DIRECTION, MINIMUM_KEPT,
                REACTION_CONSISTENCY));
        assertThat(view.injection()).isEqualTo(new PromptQualityView.Injection(1, UNCHANGED));
        assertThat(view.invariance()).isEqualTo(new PromptQualityView.Invariance(FIRST_STEP, DECISIONS, 1));
        assertThat(view.batch()).as("the figures come from three batches").isNull();
        assertThat(view.batches()).isEqualTo(batches);
        assertThat(view.comparison()).as("U6-4").isEqualTo(comparison);
        assertThat(view.raw()).as("U6-5: each figure's source with its per-run results")
                .isEqualTo(new PromptQualityView.Raw(delivery.delivery(), reaction.reaction(), injection.injection(),
                        repetitions().invariance()));
    }

    @Test
    void theOneBatchCallNamesThatBatchForEveryFigure() {
        PromptQualityView view = PromptQualityView.of(MEASURED, "f".repeat(64), "w7-2", "proto-1", report(),
                quality());

        assertThat(view.batch()).isEqualTo("w7-2");
        assertThat(view.batches()).as("N-PQ-1").isEqualTo(new PromptQualityView.Batches("w7-2", "w7-2", "w7-2"));
        assertThat(view.comparison()).isNull();
    }

    @Test
    void aFigureWithoutABatchOfItsOwnTakesTheOneBatchGiven() {
        assertThat(PromptQualityView.Batches.of("w7-2", null, "w7-r", "")).as("N-PQ-1")
                .isEqualTo(new PromptQualityView.Batches("w7-2", "w7-r", "w7-2"));
        assertThat(PromptQualityView.Batches.of(null, "d", null, "i").missing()).isEqualTo("reaction");
        assertThat(PromptQualityView.Batches.of("w7-2", null, null, null).single()).isEqualTo("w7-2");
        assertThat(PromptQualityView.Batches.of(null, "d", "r", "i").single()).isNull();
    }

    @Test
    void theComparisonGivesBothMeasurementsByOneDefinition() {
        // U6-4: the v19 numbers of the design (67/90 attack runs reacted, 8/66 normal runs asked to verify).
        PromptQualityView.Comparison comparison = PromptQualityView.Comparison.of("protocol-v19", "2026.10.16-v19.20",
                "2026.10.16-v20.24", new RunLevelReaction.Counts(90, 67, 66, 8, 0, 3),
                new RunLevelReaction.Counts(80, 80, 75, 2, 1, 0));

        assertThat(comparison.attackBefore()).isEqualTo(BenchmarkService.rate(67, 90));
        assertThat(comparison.attackNow()).isEqualTo(BenchmarkService.rate(80, 80));
        assertThat(comparison.normalBefore()).isEqualTo(BenchmarkService.rate(8, 66));
        assertThat(comparison.normalNow()).isEqualTo(BenchmarkService.rate(2, 75));
        assertThat(comparison.baselineBundle()).isEqualTo("2026.10.16-v19.20");
        assertThat(PromptQualityView.Comparison.of("p", null, null, new RunLevelReaction.Counts(0, 0, 0, 0, 0, 0),
                new RunLevelReaction.Counts(1, 1, 0, 0, 0, 0)).attackBefore()).as("no run to count").isNull();
    }

    private static ReactivityService.Report report() {
        return new ReactivityService.Report("w7-2", "proto-1",
                new ReactivityService.BatchDelivery(DELIVERED, Map.of("approval", DELIVERED), 0, List.of()),
                new ReactionEvaluator.Summary(116, 6, MINIMUM_KEPT, DIRECTION, REACTION_CONSISTENCY, List.of(),
                        List.of(), List.of(), List.of()),
                new InvarianceEvaluator.Invariance(FIRST_STEP, LATER_STEPS, Map.of(), DECISIONS, 0, List.of()),
                new InjectionEvaluator.Summary(6, 0, UNCHANGED, List.of()));
    }

    private static DecisionQuality quality() {
        return new DecisionQuality(ACCURACY, CONSISTENCY, REASON_MATCH, 0);
    }

    private static ReactivityService.Report part(String batch, BenchmarkView.Rate delivered,
                                                 ReactionEvaluator.Summary reacted,
                                                 InjectionEvaluator.Summary injected) {
        return new ReactivityService.Report(batch, null, new ReactivityService.BatchDelivery(delivered, Map.of(), 0,
                List.of()), reacted, null, injected);
    }

    private static ReactivityService.Report repetitions() {
        return new ReactivityService.Report(null, "proto-1", null, null,
                new InvarianceEvaluator.Invariance(FIRST_STEP, LATER_STEPS, Map.of(), DECISIONS, 0, List.of()), null);
    }

    private static ReactionEvaluator.Summary reacted() {
        return new ReactionEvaluator.Summary(116, 6, MINIMUM_KEPT, DIRECTION, REACTION_CONSISTENCY, List.of(),
                List.of(), List.of(), List.of());
    }

    private static InjectionEvaluator.Summary injected() {
        return new InjectionEvaluator.Summary(6, 0, UNCHANGED, List.of());
    }

    private static List<String> names(JsonNode node) {
        List<String> names = new ArrayList<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }
}
