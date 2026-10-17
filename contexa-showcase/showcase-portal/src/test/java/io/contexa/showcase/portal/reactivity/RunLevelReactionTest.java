package io.contexa.showcase.portal.reactivity;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * U6-4: A1 and A2 counted by run as prompt-audit/p0/run_level_reaction.py counts them for the measurement gates (the
 * P8 preregistration's A1 and A2), so the comparison line of the prompt-quality tab says what the gates measured.
 */
class RunLevelReactionTest {

    private static final Map<String, String> CLASSES = Map.of("A1", "THREAT", "A3", "THREAT", "N1", "NORMAL",
            "U1", "UNCERTAIN");

    @Test
    void runsAreCountedByClassAsTheGatesCountThem() {
        List<RunLevelReaction.Step> steps = List.of(
                step("run-a", "A1", "ALLOW"), step("run-a", "A1", "CHALLENGE"),
                step("run-b", "A1", "ALLOW"), step("run-b", "A1", "ALLOW"),
                new RunLevelReaction.Step("run-c", "A3", null, true, 1),
                new RunLevelReaction.Step("run-d", "A3", null, false, 0),
                step("run-e", "N1", "CHALLENGE"),
                step("run-f", "N1", "ALLOW"),
                step("run-g", "U1", "BLOCK"),
                step("run-h", "X9", "BLOCK"));

        RunLevelReaction.Counts counts = RunLevelReaction.count(steps, CLASSES::get);

        // run-a reacted on its second step, run-b missed, run-c (unresolved) stays in as a miss, run-d (stopped before
        // the engine) is left out; run-e asked to verify, run-f did not; run-g is UNCERTAIN; X9 has no class.
        assertThat(counts).isEqualTo(new RunLevelReaction.Counts(3, 1, 2, 1, 1, 1));
    }

    @Test
    void escalateAndBlockAreReactionsAndAllowIsNot() {
        RunLevelReaction.Counts counts = RunLevelReaction.count(List.of(step("run-1", "A1", "ESCALATE"),
                step("run-2", "A1", "BLOCK"), step("run-3", "A1", "ALLOW"), step("run-4", "N1", "ESCALATE")),
                CLASSES::get);

        assertThat(counts).isEqualTo(new RunLevelReaction.Counts(3, 2, 1, 1, 0, 0));
    }

    private static RunLevelReaction.Step step(String run, String key, String action) {
        return new RunLevelReaction.Step(run, key, action, false, 1);
    }
}
