package io.contexa.showcase.portal.reactivity;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W6-1 (P6-CHANGE-2, plan 8.5, metric A4): every variant of the reaction matrix is judged against the rules and the
 * direction written before the runs, or, for the variants that change the whole baseline or the policy family, against
 * the same function applied to the run's own sealed facts (prompt-audit/w06/refcalc.apply_rules,
 * reaction_full.expectation).
 */
class ReactionEvaluatorTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final ReactionEvaluator evaluator = ReactionEvaluator.fromResources();

    @Test
    void theMatrixHoldsEveryVariantOfThePlan() {
        assertThat(evaluator.variants()).hasSize(122);
        assertThat(evaluator.variants().stream().filter(variant -> !variant.planned())).hasSize(20);
        assertThat(evaluator.variants().stream().filter(variant -> variant.variantKey() != null)
                .map(ReactionEvaluator.Variant::variantKey)).containsExactlyInAnyOrder("S07-V1", "S10-V1", "S11-V1",
                "S12-V1");
        assertThat(evaluator.variants().stream().filter(ReactionEvaluator.Variant::planned)
                .map(ReactionEvaluator.Variant::expectedDirection).distinct())
                .containsExactlyInAnyOrder(ReactionEvaluator.AT_LEAST_CHALLENGE, ReactionEvaluator.ALLOW,
                        ReactionEvaluator.MODEL_JUDGES);
        assertThat(evaluator.variant("A3T:device=NEW").orElseThrow().conditions()).isEqualTo(Map.of("device", "NEW"));
    }

    @Test
    void anAllowOnAStepARuleHitsIsAViolationAndDisagreesWithThePlannedDirection() throws Exception {
        PromptFacts facts = facts(sensitiveExport("device Safari/18 on MAC seen 0 of 22 (unexplained)", "yes"));

        ReactionEvaluator.RunReaction reaction = evaluator.judge("run-1", "A3T:device=NEW",
                List.of(new ReactionEvaluator.Step(1, "ALLOW", List.of(), facts)));

        assertThat(reaction.run().rules()).containsExactly("P2");
        assertThat(reaction.planMatchesRun()).isTrue();
        assertThat(reaction.minimumViolation()).isTrue();
        assertThat(reaction.directionAgrees()).isFalse();
    }

    @Test
    void aComputedVariantTakesItsExpectationFromTheRunsFacts() throws Exception {
        PromptFacts facts = facts(sensitiveExport("time 03 seen 0 of 22 (explained by APR-1)", "no"));

        ReactionEvaluator.RunReaction reaction = evaluator.judge("run-1", "A3:employee=adm-c",
                List.of(new ReactionEvaluator.Step(1, "ESCALATE", List.of(new ReactionEvaluator.Finding(
                        "P3_POLICY_NOT_SATISFIED", "ESCALATE", "ESCALATE", false)), facts)));

        assertThat(reaction.planned()).isNull();
        assertThat(reaction.run().rules()).containsExactly("P3");
        assertThat(reaction.expectedDirection()).isEqualTo(ReactionEvaluator.AT_LEAST_CHALLENGE);
        assertThat(reaction.engineAgrees()).isTrue();
        assertThat(reaction.minimumViolation()).isFalse();
        assertThat(reaction.directionAgrees()).isTrue();
    }

    @Test
    void aComputedVariantWithEverythingExplainedAndSatisfiedExpectsAllow() throws Exception {
        PromptFacts facts = facts(sensitiveExport("time 03 seen 0 of 22 (explained by APR-1)", "yes"));

        ReactionEvaluator.RunReaction reaction = evaluator.judge("run-1", "A3:employee=adm-c",
                List.of(new ReactionEvaluator.Step(1, "CHALLENGE", List.of(), facts)));

        assertThat(reaction.run().rules()).isEmpty();
        assertThat(reaction.expectedDirection()).isEqualTo(ReactionEvaluator.ALLOW);
        assertThat(reaction.directionAgrees()).isFalse();
    }

    @Test
    void aClaimedTicketThatDoesNotExistLeavesTheDirectionToTheModel() throws Exception {
        PromptFacts facts = facts("""
                {"lines": [{"label": "ResourceClass", "value": "NORMAL (sensitivity INTERNAL)"},
                           {"label": "Action", "value": "READ (declared) GET"},
                           {"label": "PolicySatisfied", "value": "yes - assigned to HX-310"},
                           {"label": "Ticket", "value": "the ticket named by the requester does not exist"}]}""");

        ReactionEvaluator.Expectation expectation = ReactionEvaluator.expectation(
                List.of(new ReactionEvaluator.Step(1, "ALLOW", List.of(), facts)));

        assertThat(expectation.direction()).isEqualTo(ReactionEvaluator.MODEL_JUDGES);
    }

    @Test
    void twoUnexplainedIdentityDeviationsOnASensitiveClassMeetP1() throws Exception {
        PromptFacts facts = facts(sensitiveExport("time 03 seen 0 of 22 (unexplained); day Sun seen 0 of 22 "
                + "(unexplained); size 4,831 items, usual up to 29 items per export (explained by APR-1)", "yes"));

        assertThat(ReactionEvaluator.unexplained(facts)).containsExactly("day", "time");
        assertThat(ReactionEvaluator.expectation(List.of(new ReactionEvaluator.Step(1, "CHALLENGE", List.of(), facts)))
                .rules()).containsExactly("P1");
    }

    @Test
    void theEngineFindingsAreComparedWithTheFactRules() throws Exception {
        PromptFacts facts = facts(sensitiveExport("time 03 seen 0 of 22 (explained by APR-1)", "no"));

        ReactionEvaluator.RunReaction reaction = evaluator.judge("run-1", "A3:employee=adm-c",
                List.of(new ReactionEvaluator.Step(1, "ESCALATE", List.of(), facts)));

        assertThat(reaction.engineAgrees()).isFalse();
    }

    @Test
    void aPlanTheRunsFactsDoNotMeetIsReported() throws Exception {
        PromptFacts facts = facts(sensitiveExport("time 03 seen 0 of 22 (explained by APR-1)", "yes"));

        ReactionEvaluator.RunReaction reaction = evaluator.judge("run-1", "A3T:device=NEW",
                List.of(new ReactionEvaluator.Step(1, "CHALLENGE", List.of(), facts)));

        assertThat(reaction.planMatchesRun()).isFalse();
        assertThat(evaluator.summarise(List.of(reaction), 0).planMismatches()).containsExactly("A3T:device=NEW");
    }

    @Test
    void aChallengeBelowTheEnginesP3FloorIsAViolation() throws Exception {
        PromptFacts facts = facts(sensitiveExport("time 03 seen 0 of 22 (explained by APR-1)", "no"));

        ReactionEvaluator.RunReaction reaction = evaluator.judge("run-1", "A3:employee=adm-c",
                List.of(new ReactionEvaluator.Step(1, "CHALLENGE", List.of(new ReactionEvaluator.Finding(
                        "P3_POLICY_NOT_SATISFIED", "ESCALATE", "CHALLENGE", true)), facts)));

        assertThat(reaction.minimumViolation()).isTrue();
        assertThat(reaction.decidedBelowMinimum()).isEqualTo(1);
    }

    @Test
    void theSummaryCountsRepeatsAgainstTheirMostFrequentAction() throws Exception {
        PromptFacts facts = facts(sensitiveExport("device Safari/18 on MAC seen 0 of 22 (unexplained)", "yes"));
        List<ReactionEvaluator.RunReaction> reactions = List.of(
                evaluator.judge("run-1", "A3T:device=NEW", List.of(new ReactionEvaluator.Step(1, "CHALLENGE",
                        List.of(), facts))),
                evaluator.judge("run-2", "A3T:device=NEW", List.of(new ReactionEvaluator.Step(1, "CHALLENGE",
                        List.of(), facts))),
                evaluator.judge("run-3", "A3T:device=NEW", List.of(new ReactionEvaluator.Step(1, "ALLOW",
                        List.of(), facts))));

        ReactionEvaluator.Summary summary = evaluator.summarise(reactions, 2);

        assertThat(summary.consistency().hits()).isEqualTo(2);
        assertThat(summary.consistency().total()).isEqualTo(3);
        assertThat(summary.consistencyBelow95()).containsExactly("A3T:device=NEW");
        assertThat(summary.minimumKept().hits()).isEqualTo(2);
        assertThat(summary.direction().hits()).isEqualTo(2);
        assertThat(summary.notInMatrix()).isEqualTo(2);
    }

    private static String sensitiveExport(String deviations, String satisfied) {
        return """
                {"lines": [{"label": "Action", "value": "EXPORT (declared) POST"},
                           {"label": "ResourceClass", "value": "CRITICAL (sensitivity CRITICAL)"},
                           {"label": "DeviationsFromBaseline", "value": "1 of 10 compared -> %s"},
                           {"label": "PolicySatisfied", "value": "%s - approval APR-1"}]}"""
                .formatted(deviations, satisfied);
    }

    private static PromptFacts facts(String json) throws Exception {
        return PromptFacts.of(JSON.readTree(json));
    }
}
