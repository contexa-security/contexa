package io.contexa.contexacore.autonomous.context.support;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The common four-level information classification maps onto the engine's sensitivity levels; its top level,
 * RESTRICTED, must not fall through as unavailable.
 */
class SecuritySemanticNormalizerSensitivityTest {

    @Test
    void theFourLevelClassificationMapsOntoTheEngineLevels() {
        assertThat(SecuritySemanticNormalizer.normalizeSensitivity("PUBLIC")).isEqualTo("LOW");
        assertThat(SecuritySemanticNormalizer.normalizeSensitivity("INTERNAL")).isEqualTo("MEDIUM");
        assertThat(SecuritySemanticNormalizer.normalizeSensitivity("CONFIDENTIAL")).isEqualTo("HIGH");
        assertThat(SecuritySemanticNormalizer.normalizeSensitivity("RESTRICTED")).isEqualTo("CRITICAL");
        assertThat(SecuritySemanticNormalizer.normalizeSensitivity("restricted")).isEqualTo("CRITICAL");
    }

    @Test
    void existingLevelsAreUnchanged() {
        assertThat(SecuritySemanticNormalizer.normalizeSensitivity("CRITICAL")).isEqualTo("CRITICAL");
        assertThat(SecuritySemanticNormalizer.normalizeSensitivity("HIGH")).isEqualTo("HIGH");
        assertThat(SecuritySemanticNormalizer.normalizeSensitivity("SECRET")).isEqualTo("HIGH");
        assertThat(SecuritySemanticNormalizer.normalizeSensitivity("MEDIUM")).isEqualTo("MEDIUM");
        assertThat(SecuritySemanticNormalizer.normalizeSensitivity("LOW")).isEqualTo("LOW");
        assertThat(SecuritySemanticNormalizer.normalizeSensitivity("UNKNOWN")).isEqualTo("UNKNOWN");
        assertThat(SecuritySemanticNormalizer.normalizeSensitivity((Object) null)).isNull();
    }
}
