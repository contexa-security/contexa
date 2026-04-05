package io.contexa.autoconfigure.properties;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("ContexaProperties")
class ContexaPropertiesTest {

    @Nested
    @DisplayName("Default values")
    class DefaultValues {

        @Test
        @DisplayName("Should have enabled=true by default")
        void shouldBeEnabledByDefault() {
            ContexaProperties properties = new ContexaProperties();

            assertThat(properties.isEnabled()).isTrue();
        }

        @Test
        @DisplayName("Should have STANDALONE infrastructure mode by default")
        void shouldBeStandaloneByDefault() {
            ContexaProperties properties = new ContexaProperties();

            assertThat(properties.getInfrastructure().getMode())
                    .isEqualTo(ContexaProperties.InfrastructureMode.STANDALONE);
        }

        @Test
        @DisplayName("Should have HCAD enabled with default similarity thresholds")
        void shouldHaveHcadDefaults() {
            ContexaProperties properties = new ContexaProperties();

            assertThat(properties.getHcad().isEnabled()).isTrue();
            assertThat(properties.getHcad().getSimilarity().getHotPathThreshold()).isEqualTo(0.7);
            assertThat(properties.getHcad().getBaseline().getMinSamples()).isEqualTo(10);
            assertThat(properties.getHcad().getBaseline().getCacheTtl()).isEqualTo(3600);
        }

        @Test
        @DisplayName("Should have autonomous defaults")
        void shouldHaveAutonomousDefaults() {
            ContexaProperties properties = new ContexaProperties();

            assertThat(properties.getAutonomous().isEnabled()).isTrue();
            assertThat(properties.getAutonomous().getEventTimeout()).isEqualTo(30000L);
        }

        @Test
        @DisplayName("Should have LLM defaults")
        void shouldHaveLlmDefaults() {
            ContexaProperties properties = new ContexaProperties();

            assertThat(properties.getLlm().isEnabled()).isTrue();
            assertThat(properties.getLlm().isAdvisorEnabled()).isTrue();
            assertThat(properties.getLlm().getChatModelPriority()).isEqualTo("ollama,anthropic,openai");
            assertThat(properties.getLlm().getEmbeddingModelPriority()).isEqualTo("ollama,openai");
        }

        @Test
        @DisplayName("Should have feedback enabled by default")
        void shouldHaveFeedbackEnabled() {
            ContexaProperties properties = new ContexaProperties();
        }
    }

    @Nested
    @DisplayName("Property binding")
    class PropertyBinding {

        @Test
        @DisplayName("Should allow setting infrastructure mode to DISTRIBUTED")
        void shouldSetDistributedMode() {
            ContexaProperties properties = new ContexaProperties();
            properties.getInfrastructure().setMode(ContexaProperties.InfrastructureMode.DISTRIBUTED);

            assertThat(properties.getInfrastructure().getMode())
                    .isEqualTo(ContexaProperties.InfrastructureMode.DISTRIBUTED);
        }

        @Test
        @DisplayName("Should allow disabling features")
        void shouldDisableFeatures() {
            ContexaProperties properties = new ContexaProperties();
            properties.setEnabled(false);
            properties.getHcad().setEnabled(false);
            properties.getAutonomous().setEnabled(false);

            assertThat(properties.isEnabled()).isFalse();
            assertThat(properties.getHcad().isEnabled()).isFalse();
            assertThat(properties.getAutonomous().isEnabled()).isFalse();
        }

        @Test
        @DisplayName("Should allow RAG configuration")
        void shouldConfigureRag() {
            ContexaProperties properties = new ContexaProperties();
            properties.getRag().setEnabled(false);

            assertThat(properties.getRag().isEnabled()).isFalse();
        }

        @Test
        @DisplayName("InfrastructureMode enum should have exactly two values")
        void shouldHaveTwoModes() {
            ContexaProperties.InfrastructureMode[] modes = ContexaProperties.InfrastructureMode.values();

            assertThat(modes).hasSize(2);
            assertThat(modes).containsExactlyInAnyOrder(
                    ContexaProperties.InfrastructureMode.STANDALONE,
                    ContexaProperties.InfrastructureMode.DISTRIBUTED);
        }
    }
}
