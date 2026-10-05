/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.autoconfigure.properties;

import io.contexa.autoconfigure.core.autonomous.CoreSaasForwardingAutoConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
            assertThat(properties.getLlm().getEmbeddingModelPriority()).isEqualTo("openai");
            assertThat(properties.getLlm().getChat().getOllama().getBaseUrl()).isEmpty();
            assertThat(properties.getLlm().getChat().getOllama().getModel()).isEmpty();
            assertThat(properties.getLlm().getChat().getOllama().getKeepAlive()).isEmpty();
            assertThat(properties.getLlm().getEmbedding().getDimensionMode())
                    .isEqualTo(ContexaProperties.Llm.Embedding.DimensionMode.MODEL_AWARE);
            assertThat(properties.getLlm().getEmbedding().getDimensions()).isEqualTo(1024);
            assertThat(properties.getLlm().getEmbedding().getOllama().isDedicatedRuntimeEnabled()).isFalse();
            assertThat(properties.getLlm().getEmbedding().getOllama().getBaseUrl()).isEmpty();
            assertThat(properties.getLlm().getEmbedding().getOllama().getModel()).isEmpty();
            assertThat(properties.getLlm().getEmbedding().getOllama().getDimensions()).isEqualTo(1024);
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
            properties.getAutonomous().setEnabled(false);

            assertThat(properties.isEnabled()).isFalse();
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

    @Nested
    @DisplayName("SaaS pseudonymization secrets")
    class SaasSecrets {

        private static final String STRONG_PSEUDONYMIZATION_SECRET = "tenant-pseudonymization-secret-0123456789abcdef";
        private static final String STRONG_CORRELATION_SECRET = "global-correlation-secret-0123456789abcdef";

        @Test
        @DisplayName("Disabled SaaS forwarding keeps accepting the development defaults")
        void disabledSaasAcceptsDefaults() {
            ContexaProperties.Saas saas = new ContexaProperties().getSaas();

            assertThat(saas.isEnabled()).isFalse();
            assertThat(saas.getPseudonymizationSecret()).isEqualTo(ContexaProperties.Saas.DEFAULT_DEV_PSEUDONYMIZATION_SECRET);
            assertThatCode(saas::validate).doesNotThrowAnyException();
            assertThatCode(saas::validateSecrets).doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Enabled SaaS forwarding rejects the development pseudonymization secret")
        void enabledSaasRejectsDefaultPseudonymizationSecret() {
            ContexaProperties.Saas saas = enabledSaas(
                    ContexaProperties.Saas.DEFAULT_DEV_PSEUDONYMIZATION_SECRET, STRONG_CORRELATION_SECRET);

            assertThatThrownBy(saas::validate)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("contexa.saas.pseudonymization-secret")
                    .hasMessageContaining("development value");
        }

        @Test
        @DisplayName("Enabled SaaS forwarding rejects the development correlation secret in either property")
        void enabledSaasRejectsDefaultCorrelationSecret() {
            assertThatThrownBy(enabledSaas(STRONG_PSEUDONYMIZATION_SECRET,
                    ContexaProperties.Saas.DEFAULT_DEV_GLOBAL_CORRELATION_SECRET)::validateSecrets)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("contexa.saas.global-correlation-secret");
            assertThatThrownBy(enabledSaas(ContexaProperties.Saas.DEFAULT_DEV_GLOBAL_CORRELATION_SECRET,
                    STRONG_CORRELATION_SECRET)::validateSecrets)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("contexa.saas.pseudonymization-secret");
        }

        @Test
        @DisplayName("Enabled SaaS forwarding rejects blank and shorter than 32 byte secrets")
        void enabledSaasRejectsBlankAndShortSecrets() {
            assertThatThrownBy(enabledSaas(" ", STRONG_CORRELATION_SECRET)::validateSecrets)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("must be configured");
            assertThatThrownBy(enabledSaas(STRONG_PSEUDONYMIZATION_SECRET, "a".repeat(31))::validateSecrets)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("contexa.saas.global-correlation-secret")
                    .hasMessageContaining("at least 32 bytes");
            assertThatCode(enabledSaas("a".repeat(32), STRONG_CORRELATION_SECRET)::validateSecrets)
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Enabled SaaS forwarding rejects an unresolved placeholder that would pass the length check")
        void enabledSaasRejectsUnresolvedPlaceholderSecret() {
            String unresolved = "${CONTEXA_SAAS_PSEUDONYMIZATION_SECRET}";
            assertThat(unresolved.getBytes(StandardCharsets.UTF_8).length).isGreaterThanOrEqualTo(32);

            assertThatThrownBy(enabledSaas(unresolved, STRONG_CORRELATION_SECRET)::validateSecrets)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("contexa.saas.pseudonymization-secret")
                    .hasMessageContaining("unresolved placeholder");
            assertThatThrownBy(enabledSaas(STRONG_PSEUDONYMIZATION_SECRET,
                    " ${CONTEXA_SAAS_GLOBAL_CORRELATION_SECRET} ")::validateSecrets)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("contexa.saas.global-correlation-secret");
            assertThatCode(enabledSaas("x${not-a-placeholder}" + "a".repeat(32), STRONG_CORRELATION_SECRET)::validateSecrets)
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Enabled SaaS forwarding accepts deployment specific secrets")
        void enabledSaasAcceptsDeploymentSecrets() {
            ContexaProperties.Saas saas = enabledSaas(STRONG_PSEUDONYMIZATION_SECRET, STRONG_CORRELATION_SECRET);

            assertThatCode(saas::validate).doesNotThrowAnyException();
        }

        @Test
        @DisplayName("SaaS forwarding properties cannot be created with the development secrets")
        void saasForwardingPropertiesRejectDefaultSecrets() {
            ContexaProperties properties = new ContexaProperties();
            properties.getSaas().setEnabled(true);
            CoreSaasForwardingAutoConfiguration configuration = new CoreSaasForwardingAutoConfiguration();

            assertThatThrownBy(() -> configuration.saasForwardingProperties(properties))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("contexa.saas.pseudonymization-secret");

            properties.getSaas().setPseudonymizationSecret(STRONG_PSEUDONYMIZATION_SECRET);
            properties.getSaas().setGlobalCorrelationSecret(STRONG_CORRELATION_SECRET);

            assertThat(configuration.saasForwardingProperties(properties).getPseudonymizationSecret())
                    .isEqualTo(STRONG_PSEUDONYMIZATION_SECRET);
        }

        private ContexaProperties.Saas enabledSaas(String pseudonymizationSecret, String globalCorrelationSecret) {
            ContexaProperties.Saas saas = new ContexaProperties().getSaas();
            saas.setEnabled(true);
            saas.setPseudonymizationSecret(pseudonymizationSecret);
            saas.setGlobalCorrelationSecret(globalCorrelationSecret);
            return saas;
        }
    }
}
