package io.contexa.contexacore.verification.inspection;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/** R1b-9: what nothing uses is gone - the result store's latest lookup and the checks' second constructors. */
class PromptInspectionCleanupShapeTest {

    @Test
    void theResultStoreHasNoLatestLookup() {
        assertThat(Arrays.stream(PromptInspectionResultStore.class.getMethods()).map(Method::getName))
                .doesNotContain("findLatest");
    }

    @Test
    void eachCoreCheckHasOneConstructor() {
        for (PromptInspectionCheck check : PromptInspector.coreChecks()) {
            assertThat(check.getClass().getConstructors()).as(check.code()).hasSize(1);
        }
    }
}
