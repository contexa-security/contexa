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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.client.ProviderAwareChatOptionsFactory;
import io.contexa.contexacore.std.llm.exception.ModelSelectionException;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeCatalog;
import io.contexa.contexacore.std.llm.strategy.DynamicModelSelectionStrategy;
import org.junit.jupiter.api.AfterEach;
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
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The layer models named in application.yml (docs/showcase/판정층-수정계획.md E-7, ET-4): a model id with no runtime
 * binding is made from the primary chat model, the layer's analysis then runs on it (the selection records it, no
 * fallback), and a layer model that cannot be made is told once at the start, with the model that runs in its place.
 */
class TieredLayerModelTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final LlmRuntimeCatalog noBindings = mock(LlmRuntimeCatalog.class);
    private final Logger logger = (Logger) LoggerFactory.getLogger(TieredLayerModelVerifier.class);
    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private TieredLLMProperties properties;
    private OpenAiChatModel primary;

    @AfterEach
    void releaseLogs() {
        logger.detachAppender(logged);
    }

    @BeforeEach
    void setUp() {
        logged.start();
        logger.addAppender(logged);
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

    /**
     * Q-22 (PR-78): a layer model that cannot be made no longer stops the start. This case asked for the stop; the
     * decision is that an application that ran stays running whatever model is set, so the start says once which layer
     * runs on which model instead. The stop never happened anyway: the verifier was not registered.
     */
    @Test
    @DisplayName("a layer model that cannot be made leaves the start going and says which model runs in its place")
    void aLayerModelThatCannotBeMadeIsToldInOneErrorLine() {
        AnthropicChatModel anthropic = anthropic("claude-haiku-5-5");
        properties.getLayer1().setModel("claude-haiku-5-5");
        DynamicModelRegistry registry = registry(anthropic);

        assertThatCode(() -> new TieredLayerModelVerifier(registry, properties, () -> anthropic)
                .afterSingletonsInstantiated()).doesNotThrowAnyException();

        assertThat(errors()).singleElement().satisfies(line -> assertThat(line)
                .contains("contexa.security.tiered.llm.layer2.model", "gpt-6.1-sol", "layer 2", "claude-haiku-5-5")
                .doesNotContain("layer 1"));
    }

    /** Q-22: the selection takes a layer's backup model before the primary one, so the line names the backup. */
    @Test
    @DisplayName("the line names the backup model when the layer has one that can be made")
    void theLineNamesTheBackupModel() {
        AnthropicChatModel anthropic = anthropic("claude-haiku-5-5");
        properties.getLayer1().setModel("claude-haiku-5-5");
        TieredLLMProperties.LayerConfig.BackupConfig backup = new TieredLLMProperties.LayerConfig.BackupConfig();
        backup.setModel("claude-opus-5-5");
        properties.getLayer2().setBackup(backup);

        new TieredLayerModelVerifier(registry(anthropic), properties, () -> anthropic).afterSingletonsInstantiated();

        assertThat(errors()).singleElement().satisfies(line -> assertThat(line).contains("gpt-6.1-sol", "claude-opus-5-5"));
    }

    @Test
    @DisplayName("without any chat model the line says that the layer has no model")
    void theLineSaysWhenNoModelIsLeft() {
        new TieredLayerModelVerifier(registry(null), properties, () -> null).afterSingletonsInstantiated();

        assertThat(errors()).hasSize(2).allSatisfy(line -> assertThat(line).contains("no chat model"));
    }

    @Test
    @DisplayName("the start says nothing when both layer models are made, and when none is set")
    void madeOrUnsetLayerModelsAreNotTold() {
        new TieredLayerModelVerifier(registry(primary), properties, () -> primary).afterSingletonsInstantiated();
        TieredLLMProperties none = new TieredLLMProperties();
        new TieredLayerModelVerifier(new DynamicModelRegistry(null, none, noBindings), none, () -> primary)
                .afterSingletonsInstantiated();

        assertThat(errors()).isEmpty();
    }

    /**
     * Q-22 (PR-78): with Anthropic each layer runs on the model set for it from the settings alone. Measured before:
     * 24,832 calls, none on the second layer's model.
     */
    @Test
    @DisplayName("each layer of an Anthropic primary model runs on its own model, and the selection names it")
    void anAnthropicLayerRunsOnItsModelFromTheSettingsAlone() {
        AnthropicChatModel anthropic = anthropic("claude-haiku-5-5");
        properties.getLayer1().setModel("claude-haiku-5-5");
        properties.getLayer2().setModel("claude-sonnet-5-5");
        DynamicModelSelectionStrategy selection = new DynamicModelSelectionStrategy(registry(anthropic), properties,
                anthropic);
        ExecutionContext layer1 = ExecutionContext.builder().prompt(new Prompt("security prompt")).tier(1).build();
        ExecutionContext layer2 = ExecutionContext.builder().prompt(new Prompt("security prompt")).tier(2).build();

        assertThat(modelOf(selection.selectModel(layer1))).isEqualTo("claude-haiku-5-5");
        assertThat(modelOf(selection.selectModel(layer2))).isEqualTo("claude-sonnet-5-5");
        assertThat(layer2.getMetadata())
                .containsEntry("selectedModelId", "claude-sonnet-5-5")
                .containsEntry("selectedModelProvider", "anthropic")
                .containsEntry("modelSelectionFallbackUsed", false);
    }

    /**
     * Q-22 (PR-78): one chat model bean of the second layer's model pushed Spring AI's own out, and the first layer ran
     * on the second layer's model too. Its model is now made from that bean.
     */
    @Test
    @DisplayName("a single chat model of the second layer's model leaves the first layer on its own model")
    void aSingleChatModelOfTheSecondLayerLeavesTheFirstLayerOnItsModel() {
        AnthropicChatModel onlyBean = anthropic("claude-sonnet-5-5");
        properties.getLayer1().setModel("claude-haiku-5-5");
        properties.getLayer2().setModel("claude-sonnet-5-5");
        DynamicModelRegistry registry = registry(onlyBean);

        assertThat(modelOf(registry.getModel("claude-haiku-5-5"))).isEqualTo("claude-haiku-5-5");
        assertThat(modelOf(registry.getModel("claude-sonnet-5-5"))).isEqualTo("claude-sonnet-5-5");
    }

    /**
     * Q-22 (PR-78): what a call on an Anthropic layer model sends. Spring AI merges a model's default options into every
     * request and leaves no way to take one out, so a layer model that refuses sampling values needs defaults of its
     * own, or the provider answers 400 on every call of that layer. The primary model keeps its temperature.
     */
    @Test
    @DisplayName("a call on an Anthropic layer model sends its model and only what that model takes")
    void aCallOnAnAnthropicLayerModelSendsItsModel() throws Exception {
        List<String> bodies = new CopyOnWriteArrayList<>();
        HttpServer provider = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        provider.createContext("/v1/messages", exchange -> {
            bodies.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] answer = ("{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude\","
                    + "\"content\":[{\"type\":\"text\",\"text\":\"ok\"}],\"stop_reason\":\"end_turn\","
                    + "\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}").getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, answer.length);
            exchange.getResponseBody().write(answer);
            exchange.close();
        });
        provider.start();
        try {
            AnthropicChatModel older = AnthropicChatModel.builder()
                    .anthropicApi(AnthropicApi.builder().apiKey("test")
                            .baseUrl("http://127.0.0.1:" + provider.getAddress().getPort()).build())
                    .defaultOptions(AnthropicChatOptions.builder().model("claude-haiku-4-5").temperature(0.8)
                            .maxTokens(64).build())
                    .build();
            properties.getLayer1().setModel("claude-haiku-4-5");
            properties.getLayer2().setModel("claude-sonnet-5-5");
            ChatModel layer2 = registry(older).getModel("claude-sonnet-5-5");

            ProviderAwareChatOptionsFactory.normalizeModelDefaultOptionsInPlace(layer2);
            layer2.call(new Prompt("security prompt"));
            older.call(new Prompt("security prompt"));

            assertThat(bodies).hasSize(2);
            assertThat(JSON.readTree(bodies.get(0)).path("model").asText()).isEqualTo("claude-sonnet-5-5");
            assertThat(JSON.readTree(bodies.get(0)).has("temperature")).as("refused by that model").isFalse();
            assertThat(JSON.readTree(bodies.get(1)).path("model").asText()).isEqualTo("claude-haiku-4-5");
            assertThat(JSON.readTree(bodies.get(1)).path("temperature").asDouble()).isEqualTo(0.8);
        } finally {
            provider.stop(0);
        }
    }

    private static AnthropicChatModel anthropic(String model) {
        return AnthropicChatModel.builder()
                .anthropicApi(AnthropicApi.builder().apiKey("test").build())
                .defaultOptions(AnthropicChatOptions.builder().model(model).build())
                .build();
    }

    private List<String> errors() {
        return logged.list.stream().filter(event -> event.getLevel() == Level.ERROR)
                .map(ILoggingEvent::getFormattedMessage).toList();
    }
}
