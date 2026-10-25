package io.contexa.showcase.portal.ops;

import io.contexa.showcase.portal.reactivity.ReactivityRuns;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W6-1, N-INJ-6: the kind a variant's runs are recorded with, by its key. A control variant (-C), an injection variant
 * with clean text, is recorded as a base under its key, the base its injection place names (plan 8.7: the same run
 * without the text); a reaction matrix variant (-V) and an injection variant (-I) keep their kinds.
 */
class OpsControllerTest {

    @Test
    void aControlVariantKeyIsTakenAndRecordedAsABase() {
        assertThat(OpsController.variantKind("A3-C3")).isEqualTo(ReactivityRuns.Kind.BASE);
        assertThat(OpsController.variantKind("A1T-C1")).isEqualTo(ReactivityRuns.Kind.BASE);
        assertThat(OpsController.variantKind("A3-I3")).isEqualTo(ReactivityRuns.Kind.INJECTION);
        assertThat(OpsController.variantKind("S07-V1")).isEqualTo(ReactivityRuns.Kind.VARIANT);
        assertThat(OpsController.variantKind("A3")).as("a case, not a variant").isNull();
        assertThat(OpsController.variantKind("A3-X3")).isNull();
    }

    /** docs/agent DD-27: retries go only with an unanswered confirmation, and within the bound. */
    @Test
    void anAgentTaskTakesRetriesOnlyWithAnUnansweredConfirmation() {
        assertThat(OpsController.delegatorAnswerTaken(null, 0)).isTrue();
        assertThat(OpsController.delegatorAnswerTaken("APPROVE", 0)).isTrue();
        assertThat(OpsController.delegatorAnswerTaken("REPORT", 0)).isTrue();
        assertThat(OpsController.delegatorAnswerTaken("SILENT", 130)).isTrue();
        assertThat(OpsController.delegatorAnswerTaken("SILENT", 0)).isFalse();
        assertThat(OpsController.delegatorAnswerTaken("SILENT", 301)).isFalse();
        assertThat(OpsController.delegatorAnswerTaken("REPORT", 5)).isFalse();
        assertThat(OpsController.delegatorAnswerTaken(null, 5)).isFalse();
        assertThat(OpsController.delegatorAnswerTaken("IGNORE", 0)).isFalse();
    }

    /** docs/agent A6-5: an agent case is a legacy N or T case, or a measurement case (M, the attack number, A, B or N). */
    @Test
    void anAgentTaskKeyIsALegacyCaseOrAMeasurementCase() {
        for (String key : new String[] {"N1", "T5", "M07A", "M07N", "M25B", "M25A2", "M10N", "M19L", "M19LN", "VN1C", "VT1E", "VT5C"}) {
            assertThat(OpsController.agentTaskKeyTaken(key)).as(key).isTrue();
        }
        for (String key : new String[] {"M7A", "M07C", "M07", "x", "../N1", "M07A22", "S12", "", "VN1", "V1C", "VX1C",
                "VT1D", "VT1CE", "vt1c", "M19LL", "M19LA", "M19LN2", "M19NL"}) {
            assertThat(OpsController.agentTaskKeyTaken(key)).as(key).isFalse();
        }
    }
}
