package io.contexa.showcase.portal.reactivity;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W6-1 (P6-CHANGE-2): what the batch metrics read from the harness records and the decision rows: the condition and
 * value a lab run's label names, and the minimum-action findings the engine kept in a decision's records.
 */
class ReactivityServiceTest {

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
}
