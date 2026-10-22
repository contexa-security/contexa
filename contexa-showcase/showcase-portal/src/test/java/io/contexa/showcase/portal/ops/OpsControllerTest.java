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
}
