package io.contexa.showcase.portal.reactivity;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W6-1 (P6-CHANGE-2, plan 8.6, metric R2): the repetitions of a case in one measurement are its invariance variants;
 * their first-step prompts may differ only in Subject and their decisions not at all
 * (prompt-audit/w06/invariance_cases.py). N-DLV-3: a step neither repetition sealed is left out; one sealed after the
 * same earlier decisions is a failed pair; one sealed after a different earlier decision is counted apart.
 */
class InvarianceEvaluatorTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final InvarianceEvaluator evaluator = new InvarianceEvaluator(DeliveryEvaluator.fromResources());

    @Test
    void repetitionsThatDifferOnlyInTheirIdentityAreInvariant() throws Exception {
        Map<String, List<InvarianceEvaluator.Run>> repetitions = new LinkedHashMap<>();
        repetitions.put("A3|t1", List.of(
                run("run-1", "CHALLENGE", "v107dabe3a78d-adm-a", "not on call"),
                run("run-2", "CHALLENGE", "v9f03c1e2a7b1-adm-a", "not on call")));

        InvarianceEvaluator.Invariance invariance = evaluator.evaluate(repetitions);

        assertThat(invariance.firstStepFacts().hits()).isEqualTo(1);
        assertThat(invariance.firstStepFacts().total()).isEqualTo(1);
        assertThat(invariance.decisions().hits()).isEqualTo(1);
        assertThat(invariance.changedFacts()).isEmpty();
    }

    @Test
    void aChangedFactAndAChangedDecisionAreCounted() throws Exception {
        Map<String, List<InvarianceEvaluator.Run>> repetitions = new LinkedHashMap<>();
        repetitions.put("A3|t1", List.of(
                run("run-1", "CHALLENGE", "v107dabe3a78d-adm-a", "not on call"),
                run("run-2", "ALLOW", "v9f03c1e2a7b1-adm-a", "on call (HX)"),
                run("run-3", "CHALLENGE", "v5a0b1c2d3e4f-adm-a", "not on call")));

        InvarianceEvaluator.Invariance invariance = evaluator.evaluate(repetitions);

        assertThat(invariance.firstStepFacts().hits()).isEqualTo(1);
        assertThat(invariance.firstStepFacts().total()).isEqualTo(2);
        assertThat(invariance.changedFacts()).containsEntry("OnCall", 1);
        assertThat(invariance.decisions().hits()).isZero();
        assertThat(invariance.decisions().total()).isEqualTo(1);
    }

    @Test
    void aFirstStepOnlyOneRepetitionSealedIsAFailedPair() throws Exception {
        Map<String, List<InvarianceEvaluator.Run>> repetitions = new LinkedHashMap<>();
        repetitions.put("A3|t1", List.of(
                run("run-1", "CHALLENGE", "v107dabe3a78d-adm-a", "not on call"),
                new InvarianceEvaluator.Run("run-2", List.of(new InvarianceEvaluator.Step(1, "r-2", "CHALLENGE",
                        null)))));

        InvarianceEvaluator.Invariance invariance = evaluator.evaluate(repetitions);

        assertThat(invariance.notSealed()).isZero();
        assertThat(invariance.firstStepFacts().hits()).isZero();
        assertThat(invariance.firstStepFacts().total()).isEqualTo(1);
        assertThat(invariance.pairs()).extracting(InvarianceEvaluator.Pair::notCompared)
                .containsExactly("NOT_SEALED_ONE_SIDE");
    }

    @Test
    void aLaterStepOnlyOneRepetitionSealedAfterTheSameDecisionsIsAFailedPair() throws Exception {
        Map<String, List<InvarianceEvaluator.Run>> repetitions = new LinkedHashMap<>();
        repetitions.put("A1|t1", List.of(twoSteps("run-1", "ALLOW", true), twoSteps("run-2", "ALLOW", false)));

        InvarianceEvaluator.Invariance invariance = evaluator.evaluate(repetitions);

        assertThat(invariance.firstStepFacts().hits()).isEqualTo(1);
        assertThat(invariance.laterStepFacts().hits()).isZero();
        assertThat(invariance.laterStepFacts().total()).isEqualTo(1);
        assertThat(invariance.notSealed()).isZero();
        assertThat(invariance.pairs()).extracting(InvarianceEvaluator.Pair::notCompared)
                .containsExactly(null, "NOT_SEALED_ONE_SIDE");
    }

    @Test
    void aLaterStepOnlyOneRepetitionSealedAfterADifferentDecisionIsCountedApart() throws Exception {
        Map<String, List<InvarianceEvaluator.Run>> repetitions = new LinkedHashMap<>();
        repetitions.put("A1|t1", List.of(twoSteps("run-1", "ALLOW", true), twoSteps("run-2", "CHALLENGE", false)));

        InvarianceEvaluator.Invariance invariance = evaluator.evaluate(repetitions);

        assertThat(invariance.notSealedAfterDifferentDecision()).as("the decision change is R2's").isEqualTo(1);
        assertThat(invariance.notSealed()).isZero();
        assertThat(invariance.laterStepFacts().total()).isZero();
    }

    @Test
    void aStepNeitherRepetitionSealedIsLeftOutAndTheRatesStay() throws Exception {
        Map<String, List<InvarianceEvaluator.Run>> held = new LinkedHashMap<>();
        held.put("A1|t1", List.of(twoSteps("run-1", "CHALLENGE", false), twoSteps("run-2", "CHALLENGE", false)));
        Map<String, List<InvarianceEvaluator.Run>> firstOnly = new LinkedHashMap<>();
        firstOnly.put("A1|t1", List.of(
                run("run-1", "CHALLENGE", "v107dabe3a78d-adm-a", "not on call"),
                run("run-2", "CHALLENGE", "v9f03c1e2a7b1-adm-a", "not on call")));

        InvarianceEvaluator.Invariance withHeldStep = evaluator.evaluate(held);
        InvarianceEvaluator.Invariance withoutIt = evaluator.evaluate(firstOnly);

        assertThat(withHeldStep.notSealed()).as("an earlier decision held the second step in both").isEqualTo(1);
        assertThat(withHeldStep.notSealedAfterDifferentDecision()).isZero();
        assertThat(withHeldStep.firstStepFacts()).isEqualTo(withoutIt.firstStepFacts());
        assertThat(withHeldStep.laterStepFacts()).isEqualTo(withoutIt.laterStepFacts());
    }

    private static InvarianceEvaluator.Run run(String runId, String action, String subject, String onCall)
            throws Exception {
        PromptFacts facts = PromptFacts.of(JSON.readTree("""
                {"lines": [{"label": "Subject", "value": "%s (HUMAN_USER)"},
                           {"label": "OnCall", "value": "%s"}]}""".formatted(subject, onCall)));
        return new InvarianceEvaluator.Run(runId, List.of(new InvarianceEvaluator.Step(1, "r-" + runId, action,
                facts)));
    }

    /** A repetition of two steps: the first decided with the action, the second sealed and decided or neither. */
    private static InvarianceEvaluator.Run twoSteps(String runId, String firstAction, boolean secondSealed)
            throws Exception {
        PromptFacts facts = PromptFacts.of(JSON.readTree("""
                {"lines": [{"label": "Subject", "value": "v107dabe3a78d-adm-a (HUMAN_USER)"},
                           {"label": "OnCall", "value": "not on call"}]}"""));
        return new InvarianceEvaluator.Run(runId, List.of(
                new InvarianceEvaluator.Step(1, "r-" + runId + "-1", firstAction, facts),
                new InvarianceEvaluator.Step(2, "r-" + runId + "-2", secondSealed ? "ALLOW" : null,
                        secondSealed ? facts : null)));
    }
}
