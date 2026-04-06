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
            assertThat(properties.getLlm().getChat().getOllama().getBaseUrl()).isEmpty();
            assertThat(properties.getLlm().getChat().getOllama().getModel()).isEmpty();
            assertThat(properties.getLlm().getChat().getOllama().getKeepAlive()).isEmpty();
            assertThat(properties.getLlm().getEmbedding().getOllama().isDedicatedRuntimeEnabled()).isFalse();
            assertThat(properties.getLlm().getEmbedding().getOllama().getBaseUrl()).isEmpty();
            assertThat(properties.getLlm().getEmbedding().getOllama().getModel()).isEmpty();
        }

        @Test
        @DisplayName("Should have feedback enabled by default")
        void shouldHaveFeedbackEnabled() {
            ContexaProperties properties = new ContexaProperties();

            assertThat(properties.getSaas()).isNotNull();
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
        @DisplayName("Should allow chat Ollama runtime configuration")
        void shouldConfigureChatOllamaRuntime() {
            ContexaProperties properties = new ContexaProperties();
            properties.getLlm().getChat().getOllama().setBaseUrl("http://127.0.0.1:11434");
            properties.getLlm().getChat().getOllama().setModel("qwen3:8b");
            properties.getLlm().getChat().getOllama().setKeepAlive("30m");

            assertThat(properties.getLlm().getChat().getOllama().getBaseUrl()).isEqualTo("http://127.0.0.1:11434");
            assertThat(properties.getLlm().getChat().getOllama().getModel()).isEqualTo("qwen3:8b");
            assertThat(properties.getLlm().getChat().getOllama().getKeepAlive()).isEqualTo("30m");
        }

        @Test
        @DisplayName("Should allow dedicated embedding runtime configuration")
        void shouldConfigureDedicatedEmbeddingRuntime() {
            ContexaProperties properties = new ContexaProperties();
            properties.getLlm().getEmbedding().getOllama().setDedicatedRuntimeEnabled(true);
            properties.getLlm().getEmbedding().getOllama().setBaseUrl("http://127.0.0.1:11435");
            properties.getLlm().getEmbedding().getOllama().setModel("mxbai-embed-large");

            assertThat(properties.getLlm().getEmbedding().getOllama().isDedicatedRuntimeEnabled()).isTrue();
            assertThat(properties.getLlm().getEmbedding().getOllama().getBaseUrl()).isEqualTo("http://127.0.0.1:11435");
            assertThat(properties.getLlm().getEmbedding().getOllama().getModel()).isEqualTo("mxbai-embed-large");
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
