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
package io.contexa.contexacore.std.llm.model;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.exception.ModelSelectionException;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeCatalog;
import io.contexa.contexacore.std.llm.strategy.DynamicModelSelectionStrategy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.anthropic.AnthropicChatOptions;
import org.springframework.ai.anthropic.api.AnthropicApi;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.openai.OpenAiChatModel;
import org.springframework.ai.openai.OpenAiChatOptions;
import org.springframework.ai.openai.api.OpenAiApi;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The layer models named in application.yml (docs/showcase/판정층-수정계획.md E-7, ET-4): a model id with no runtime
 * binding is made from the primary chat model, the layer's analysis then runs on it (the selection records it, no
 * fallback), and a layer model that cannot be made stops the start instead of falling back to the primary model.
 */
class TieredLayerModelTest {

    private final LlmRuntimeCatalog noBindings = mock(LlmRuntimeCatalog.class);
    private TieredLLMProperties properties;
    private OpenAiChatModel primary;

    @BeforeEach
    void setUp() {
        when(noBindings.getChatBindings()).thenReturn(List.of());
        when(noBindings.findChatBinding(any())).thenReturn(Optional.empty());
        properties = new TieredLLMProperties();
        properties.getLayer1().setModel("gpt-6-luna");
        properties.getLayer2().setModel("gpt-6.1-sol");
        primary = OpenAiChatModel.builder()
                .openAiApi(OpenAiApi.builder().apiKey("test").build())
                .defaultOptions(OpenAiChatOptions.builder().model("gpt-6-luna").build())
                .build();
    }

    private DynamicModelRegistry registry(ChatModel base) {
        DynamicModelRegistry registry = new DynamicModelRegistry(null, properties, noBindings);
        if (base != null) {
            registry.setVariantBase(() -> base);
        }
        registry.initialize();
        return registry;
    }

    private static String modelOf(ChatModel model) {
        return model.getDefaultOptions().getModel();
    }

    @Test
    @DisplayName("a layer model with no binding is made from the primary chat model, once")
    void anUnboundLayerModelIsMadeFromThePrimary() {
        DynamicModelRegistry registry = registry(primary);

        ChatModel layer2 = registry.getModel("gpt-6.1-sol");

        assertThat(modelOf(layer2)).isEqualTo("gpt-6.1-sol");
        assertThat(registry.getModel("gpt-6.1-sol")).isSameAs(layer2);
        assertThat(registry.getDescriptor("gpt-6.1-sol").getProvider()).isEqualTo("openai");
    }

    @Test
    @DisplayName("the tier 2 analysis runs on the layer2 model, and the selection names it without a fallback")
    void theSecondLayerRunsOnItsModel() {
        DynamicModelSelectionStrategy selection = new DynamicModelSelectionStrategy(registry(primary), properties,
                primary);
        ExecutionContext context = ExecutionContext.builder().prompt(new Prompt("security prompt")).tier(2).build();

        ChatModel selected = selection.selectModel(context);

        assertThat(modelOf(selected)).isEqualTo("gpt-6.1-sol");
        assertThat(context.getMetadata())
                .containsEntry("selectedModelId", "gpt-6.1-sol")
                .containsEntry("modelSelectionSource", "tier:2")
                .containsEntry("modelSelectionFallbackUsed", false);
    }

    @Test
    @DisplayName("without a base, or with one that cannot be copied, an unbound layer model is not made")
    void anUnboundModelWithoutABaseIsNotMade() {
        AnthropicChatModel anthropic = AnthropicChatModel.builder()
                .anthropicApi(AnthropicApi.builder().apiKey("test").build())
                .defaultOptions(AnthropicChatOptions.builder().model("claude-haiku-5-5").build())
                .build();

        assertThatThrownBy(() -> registry(null).getModel("gpt-6.1-sol")).isInstanceOf(ModelSelectionException.class);
        assertThatThrownBy(() -> registry(anthropic).getModel("gpt-6.1-sol"))
                .isInstanceOf(ModelSelectionException.class);
    }

    @Test
    @DisplayName("the start stops when a layer model cannot be made, naming the setting and the model")
    void aLayerModelThatCannotBeMadeStopsTheStart() {
        TieredLayerModelVerifier verifier = new TieredLayerModelVerifier(registry(null), properties);

        assertThatThrownBy(verifier::afterSingletonsInstantiated)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("contexa.security.tiered.llm.layer1.model")
                .hasMessageContaining("gpt-6-luna");
    }

    @Test
    @DisplayName("the start goes on when both layer models are made, and when none is set")
    void madeOrUnsetLayerModelsLetTheStartGoOn() {
        assertThatCode(() -> new TieredLayerModelVerifier(registry(primary), properties).afterSingletonsInstantiated())
                .doesNotThrowAnyException();
        TieredLLMProperties none = new TieredLLMProperties();
        assertThatCode(() -> new TieredLayerModelVerifier(new DynamicModelRegistry(null, none, noBindings), none)
                .afterSingletonsInstantiated()).doesNotThrowAnyException();
    }
}
