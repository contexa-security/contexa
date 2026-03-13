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
            assertThat(properties.getHcad().getSimilarity().getMinimalThreshold()).isEqualTo(0.8);
            assertThat(properties.getHcad().getBaseline().getMinSamples()).isEqualTo(10);
            assertThat(properties.getHcad().getBaseline().isAutoLearning()).isTrue();
        }

        @Test
        @DisplayName("Should have autonomous defaults")
        void shouldHaveAutonomousDefaults() {
            ContexaProperties properties = new ContexaProperties();

            assertThat(properties.getAutonomous().isEnabled()).isTrue();
            assertThat(properties.getAutonomous().getStrategyMode()).isEqualTo("dynamic");
            assertThat(properties.getAutonomous().getEventTimeout()).isEqualTo(30000L);
        }

        @Test
        @DisplayName("Should have LLM defaults")
        void shouldHaveLlmDefaults() {
            ContexaProperties properties = new ContexaProperties();

            assertThat(properties.getLlm().isEnabled()).isTrue();
            assertThat(properties.getLlm().isTieredEnabled()).isTrue();
            assertThat(properties.getLlm().isAdvisorEnabled()).isTrue();
        }

        @Test
        @DisplayName("Should have simulation disabled by default")
        void shouldHaveSimulationDisabled() {
            ContexaProperties properties = new ContexaProperties();

            assertThat(properties.getSimulation().isEnabled()).isFalse();
            assertThat(properties.getSimulation().getData().isEnabled()).isFalse();
            assertThat(properties.getSimulation().getData().isClearExisting()).isFalse();
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
        @DisplayName("Should allow RAG vector store configuration")
        void shouldConfigureRag() {
            ContexaProperties properties = new ContexaProperties();
            properties.getRag().getVectorStore().setType("qdrant");
            properties.getRag().getVectorStore().setDefaultTopK(10);
            properties.getRag().getVectorStore().setDefaultSimilarityThreshold(0.9);

            assertThat(properties.getRag().getVectorStore().getType()).isEqualTo("qdrant");
            assertThat(properties.getRag().getVectorStore().getDefaultTopK()).isEqualTo(10);
            assertThat(properties.getRag().getVectorStore().getDefaultSimilarityThreshold()).isEqualTo(0.9);
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
