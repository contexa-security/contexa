package io.contexa.showcase.portal.reactivity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W6-1 (P6-CHANGE-2): what the batch metrics read from the harness records and the decision rows: the condition and
 * value a lab run's label names, and the minimum-action findings the engine kept in a decision's records. N-DLV-1: two
 * runs' decision rows compared step by step, the sealed prompts read from a stand-in for control D. A step neither run
 * sealed (an earlier decision held both), or one run sealed after an earlier step was decided differently (the
 * reaction evaluator compares the decisions), is left out; one run sealed after the same decisions, a step the variant
 * lacks, a compared step not delivered, or no compared step at all fails the runs.
 */
class ReactivityServiceTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    /** The sealed prompts control D holds, by request ID; a request without one was not sealed. */
    private final Map<String, JsonNode> sealed = new HashMap<>();
    private final ReactivityService service = new ReactivityService(new WorkloadAdmin(null, null, JSON) {
        @Override
        public Optional<JsonNode> promptFacts(String requestId) {
            return Optional.ofNullable(sealed.get(requestId));
        }
    }, null, DeliveryEvaluator.fromResources(), null, null, null);

    @Test
    void aLabLabelNamesItsConditionAndValue() {
        assertThat(ReactivityService.conditionOf("A3T:approval=False")).containsExactly("approval", "False");
        assertThat(ReactivityService.conditionOf("A3:items=4831")).containsExactly("items", "4831");
        assertThat(ReactivityService.conditionOf("A3:designed")).isNull();
    }

    @Test
    void theFindingsAreReadFromTheRecordsMetadata() throws Exception {
        String records = """
                [{"metadataJson": "{\\"minimumActionFindings\\": [{\\"rule\\": \\"P3_POLICY_NOT_SATISFIED\\", \
                \\"requiredAction\\": \\"ESCALATE\\", \\"decidedAction\\": \\"CHALLENGE\\", \\"violated\\": true}]}"},
                 {"metadataJson": {"minimumActionFindings": [{"rule": "P1_IDENTITY_DEVIATION",
                   "requiredAction": "CHALLENGE", "decidedAction": "CHALLENGE", "violated": false}]}},
                 {"metadataJson": ""}]""";

        assertThat(ReactivityService.findings(records)).containsExactly(
                new ReactionEvaluator.Finding("P3_POLICY_NOT_SATISFIED", "ESCALATE", "CHALLENGE", true),
                new ReactionEvaluator.Finding("P1_IDENTITY_DEVIATION", "CHALLENGE", "CHALLENGE", false));
    }

    @Test
    void aStepNeitherRunSealedIsLeftOutOfTheVerdict() throws Exception {
        seal("req-base-1", "req-lab-1");

        ReactivityService.RunDelivery delivery = service.delivery("run-base", "run-lab",
                decisions("req-base", "CHALLENGE", null), decisions("req-lab", "CHALLENGE", null),
                DeliveryEvaluator.INVARIANT, null);

        assertThat(delivery.steps()).extracting(ReactivityService.StepDelivery::notCompared)
                .containsExactly(null, "NOT_SEALED");
        assertThat(delivery.passed()).as("an earlier decision held the second step in both runs").isTrue();
    }

    @Test
    void aStepOnlyOneRunSealedAfterTheSameDecisionsFailsTheRuns() throws Exception {
        seal("req-base-1", "req-lab-1", "req-base-2");
        ReactivityService.RunDelivery baseOnly = service.delivery("run-base", "run-lab",
                decisions("req-base", "ALLOW", "ALLOW"), decisions("req-lab", "ALLOW", null),
                DeliveryEvaluator.INVARIANT, null);
        sealed.remove("req-base-2");
        seal("req-lab-2");
        ReactivityService.RunDelivery variantOnly = service.delivery("run-base", "run-lab",
                decisions("req-base", "ALLOW", null), decisions("req-lab", "ALLOW", "ALLOW"),
                DeliveryEvaluator.INVARIANT, null);

        assertThat(baseOnly.steps().get(1).notCompared()).isEqualTo("NOT_SEALED_ONE_SIDE");
        assertThat(baseOnly.passed()).isFalse();
        assertThat(variantOnly.steps().get(1).notCompared()).isEqualTo("NOT_SEALED_ONE_SIDE");
        assertThat(variantOnly.passed()).isFalse();
    }

    @Test
    void aStepOnlyOneRunSealedAfterADifferentEarlierDecisionIsLeftOut() throws Exception {
        seal("req-base-1", "req-lab-1", "req-base-2");

        ReactivityService.RunDelivery delivery = service.delivery("run-base", "run-lab",
                decisions("req-base", "ALLOW", "ALLOW"), decisions("req-lab", "CHALLENGE", null),
                DeliveryEvaluator.INVARIANT, null);

        assertThat(delivery.steps().get(1).notCompared()).isEqualTo("NOT_SEALED_AFTER_DIFFERENT_DECISION");
        assertThat(delivery.passed()).as("the reaction evaluator compares the first step's decisions").isTrue();
    }

    @Test
    void aStepTheVariantDoesNotHaveFailsTheRuns() throws Exception {
        seal("req-base-1", "req-lab-1", "req-base-2");

        ReactivityService.RunDelivery delivery = service.delivery("run-base", "run-lab",
                decisions("req-base", "ALLOW", "ALLOW"), decisions("req-lab", "ALLOW"), DeliveryEvaluator.INVARIANT,
                null);

        assertThat(delivery.steps().get(1).notCompared()).isEqualTo("NO_VARIANT_STEP");
        assertThat(delivery.passed()).isFalse();
    }

    @Test
    void aComparedStepThatWasNotDeliveredFailsTheRunsBesideAStepLeftOut() throws Exception {
        seal("req-base-1");
        sealed.put("req-lab-1", JSON.readTree("""
                {"lines": [{"label": "Network", "value": "203.0.113.0/24 zone EXTERNAL"},
                           {"label": "Time", "value": "03:17 Wed"}]}"""));

        ReactivityService.RunDelivery delivery = service.delivery("run-base", "run-lab",
                decisions("req-base", "CHALLENGE", null), decisions("req-lab", "CHALLENGE", null),
                DeliveryEvaluator.INVARIANT, null);

        assertThat(delivery.steps().get(0).delivery().unexpected()).containsExactly("Network");
        assertThat(delivery.steps().get(1).notCompared()).isEqualTo("NOT_SEALED");
        assertThat(delivery.passed()).isFalse();
    }

    @Test
    void runsWithoutAComparedStepFail() throws Exception {
        ReactivityService.RunDelivery unsealed = service.delivery("run-base", "run-lab",
                decisions("req-base", "CHALLENGE"), decisions("req-lab", "CHALLENGE"), DeliveryEvaluator.INVARIANT,
                null);
        seal("req-base-2");
        ReactivityService.RunDelivery leftOut = service.delivery("run-base", "run-lab",
                decisions("req-base", "ALLOW", "ALLOW"), decisions("req-lab", "CHALLENGE", null),
                DeliveryEvaluator.INVARIANT, null);
        ReactivityService.RunDelivery empty = service.delivery("run-base", "run-lab", List.of(), List.of(),
                DeliveryEvaluator.INVARIANT, null);

        assertThat(unsealed.steps()).extracting(ReactivityService.StepDelivery::notCompared)
                .containsExactly("NOT_SEALED");
        assertThat(unsealed.passed()).as("no fact was compared").isFalse();
        assertThat(leftOut.steps()).extracting(ReactivityService.StepDelivery::notCompared)
                .containsExactly("NOT_SEALED", "NOT_SEALED_AFTER_DIFFERENT_DECISION");
        assertThat(leftOut.passed()).as("every step left out").isFalse();
        assertThat(empty.passed()).isFalse();
    }

    @Test
    void eachStepIsComparedWithItsNumber() throws Exception {
        seal("req-base-1", "req-lab-1");
        sealed.put("req-base-2", JSON.readTree("""
                {"lines": [{"label": "RequestsInSession", "value": "1 so far: 14:20 EXPORT -> ALLOW"}]}"""));
        sealed.put("req-lab-2", JSON.readTree("""
                {"lines": [{"label": "RequestsInSession", "value": "1 so far: 03:17 EXPORT -> ALLOW"}]}"""));

        ReactivityService.RunDelivery delivery = service.delivery("run-base", "run-lab",
                decisions("req-base", "ALLOW", "ALLOW"), decisions("req-lab", "ALLOW", "ALLOW"),
                DeliveryEvaluator.INVARIANT, null);

        assertThat(delivery.steps().get(1).delivery().derived()).as("N-DLV-5: a later step's session line")
                .containsExactly("RequestsInSession");
        assertThat(delivery.passed()).isTrue();
    }

    @Test
    void theRunsWhoseFirstStepIsTheBaseItselfAreCountedApart() throws Exception {
        sealed.put("req-base-1", JSON.readTree("""
                {"lines": [{"label": "OnCall", "value": "on call (HX on-call)"}]}"""));
        sealed.put("req-lab-1", JSON.readTree("""
                {"lines": [{"label": "OnCall", "value": "on call (HX on-call)"}]}"""));

        ReactivityService.RunDelivery same = service.delivery("run-base", "run-lab",
                decisions("req-base", "CHALLENGE"), decisions("req-lab", "CHALLENGE"), "onCall", "true");

        assertThat(same.passed()).as("N-DLV-6: the base was on call already").isTrue();
        assertThat(ReactivityService.sameAsBase(List.of(same))).isEqualTo(1);
    }

    /** The same sealed prompt for each request: compared under the invariant condition, nothing changed. */
    private void seal(String... requestIds) throws Exception {
        for (String requestId : requestIds) {
            sealed.put(requestId, JSON.readTree("""
                    {"lines": [{"label": "Network", "value": "10.40.12.0/24 zone CORPORATE"},
                               {"label": "Time", "value": "03:17 Wed"}]}"""));
        }
    }

    /** A run's decision rows: requests prefix-1, prefix-2 and so on, with their final actions in step order. */
    private static List<ReactivityService.Decision> decisions(String prefix, String... finalActions) {
        List<ReactivityService.Decision> decisions = new ArrayList<>();
        for (int i = 0; i < finalActions.length; i++) {
            decisions.add(new ReactivityService.Decision(i + 1, prefix + "-" + (i + 1), finalActions[i], null));
        }
        return decisions;
    }
}
