package io.contexa.sandbox.fullstack.prompt;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SandboxPromptCompressionImpactBenchmarkSettingsTest {

    @AfterEach
    void tearDown() {
        System.clearProperty("sandbox.decision.real-llm");
        System.clearProperty("sandbox.compression.profile-matrix");
        System.clearProperty("sandbox.compression.baseline-profile");
        System.clearProperty("sandbox.compression.candidate-profile");
    }

    @Test
    @DisplayName("real LLM official compression benchmark defaults to direct raw-versus-candidate comparison")
    void shouldDefaultRealLlmMatrixToBaselineAndCandidateOnly() {
        System.setProperty("sandbox.decision.real-llm", "true");

        assertThat(SandboxPromptCompressionImpactBenchmarkSettings.baselineProfile())
                .isEqualTo("CORTEX_L1_RAW_IDENTITY");
        assertThat(SandboxPromptCompressionImpactBenchmarkSettings.candidateProfile())
                .isEqualTo("CORTEX_L1_DECISION_COMPACT");
        assertThat(SandboxPromptCompressionImpactBenchmarkSettings.profileMatrix())
                .containsExactly(
                        "CORTEX_L1_RAW_IDENTITY",
                        "CORTEX_L1_DECISION_COMPACT");
    }

    @Test
    @DisplayName("explicit profile matrix still overrides the real LLM default")
    void shouldHonorExplicitProfileMatrixOverride() {
        System.setProperty("sandbox.decision.real-llm", "true");
        System.setProperty(
                "sandbox.compression.profile-matrix",
                "CORTEX_L1_RAW_IDENTITY,CORTEX_L1_STANDARD,CORTEX_L1_COMPACT,CORTEX_L1_DECISION_COMPACT");

        assertThat(SandboxPromptCompressionImpactBenchmarkSettings.profileMatrix())
                .containsExactly(
                        "CORTEX_L1_RAW_IDENTITY",
                        "CORTEX_L1_STANDARD",
                        "CORTEX_L1_COMPACT",
                        "CORTEX_L1_DECISION_COMPACT");
    }

    @Test
    @DisplayName("stable benchmark mode keeps the broader local comparison matrix")
    void shouldKeepBroaderMatrixForStableMode() {
        assertThat(SandboxPromptCompressionImpactBenchmarkSettings.profileMatrix())
                .isEqualTo(List.of(
                        "CORTEX_L1_RAW_IDENTITY",
                        "CORTEX_L1_STANDARD",
                        "CORTEX_L1_COMPACT"));
    }
}
