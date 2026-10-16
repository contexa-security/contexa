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

        assertThat(names(view)).containsExactlyInAnyOrder("measuredAt", "setting", "batch", "protocol", "delivery",
                "reaction", "invariance", "injection", "accuracy", "consistency", "reasonMatch");
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

    private static ReactivityService.Report report() {
        return new ReactivityService.Report("w7-2", "proto-1",
                new ReactivityService.BatchDelivery(DELIVERED, Map.of("approval", DELIVERED), 0, List.of()),
                new ReactionEvaluator.Summary(116, 6, MINIMUM_KEPT, DIRECTION, REACTION_CONSISTENCY, List.of(),
                        List.of(), List.of(), List.of()),
                new InvarianceEvaluator.Invariance(FIRST_STEP, LATER_STEPS, Map.of(), DECISIONS, 0, List.of()),
                new InjectionEvaluator.Summary(6, 0, UNCHANGED, List.of()));
    }

    private static List<String> names(JsonNode node) {
        List<String> names = new ArrayList<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }
}
