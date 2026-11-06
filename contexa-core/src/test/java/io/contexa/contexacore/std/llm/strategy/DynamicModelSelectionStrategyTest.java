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
package io.contexa.contexacore.std.llm.strategy;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.model.DynamicModelRegistry;
import io.contexa.contexacore.std.llm.model.ModelDescriptor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.anthropic.AnthropicChatOptions;
import org.springframework.ai.anthropic.api.AnthropicApi;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.prompt.Prompt;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DynamicModelSelectionStrategyTest {

    @Mock
    private DynamicModelRegistry modelRegistry;

    @Mock
    private ChatModel primaryChatModel;

    @Mock
    private ChatModel explicitModel;

    @Mock
    private ChatModel tierModel;

    private final Logger logger = (Logger) LoggerFactory.getLogger(DynamicModelSelectionStrategy.class);

    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();

    @BeforeEach
    void captureLogs() {
        logged.start();
        logger.addAppender(logged);
    }

    @AfterEach
    void releaseLogs() {
        logger.detachAppender(logged);
    }

    private List<ILoggingEvent> alarms() {
        return logged.list.stream().filter(event -> event.getLevel().isGreaterOrEqual(Level.WARN)).toList();
    }

    /** The next candidate took over and the decision ran: on every decision a warning here read as a failing model. */
    @Test
    void aTierModelThatGivesWayToTheNextCandidateRaisesNoAlarm() {
        TieredLLMProperties properties = new TieredLLMProperties();
        properties.getLayer1().setModel("tier-model");
        DynamicModelSelectionStrategy strategy = new DynamicModelSelectionStrategy(modelRegistry, properties, primaryChatModel);
        when(modelRegistry.getModel("tier-model")).thenThrow(new IllegalStateException("missing"));
        ExecutionContext context = ExecutionContext.builder().tier(1).build();

        assertThat(strategy.selectModel(context)).isSameAs(primaryChatModel);

        assertThat(alarms()).isEmpty();
        assertThat(context.getMetadata())
                .containsEntry("modelSelectionSource", "primary_chat_model")
                .containsEntry("modelSelectionFallbackUsed", true);
    }

    @Test
    void aRequestedModelThatGivesWayToTheTierModelRaisesNoAlarm() {
        TieredLLMProperties properties = new TieredLLMProperties();
        properties.getLayer1().setModel("tier-model");
        DynamicModelSelectionStrategy strategy = new DynamicModelSelectionStrategy(modelRegistry, properties, primaryChatModel);
        when(modelRegistry.getModel("missing-model")).thenThrow(new IllegalStateException("missing"));
        when(modelRegistry.getModel("tier-model")).thenReturn(tierModel);

        assertThat(strategy.selectModel(ExecutionContext.builder().preferredModel("missing-model").tier(1).build()))
                .isSameAs(tierModel);

        assertThat(alarms()).isEmpty();
    }

    /** With no candidate left there is nothing to judge with: that is said, once, with what was tried. */
    @Test
    void noCandidateLeftIsReportedOnceWithWhatWasTried() {
        TieredLLMProperties properties = new TieredLLMProperties();
        properties.getLayer1().setModel("tier-model");
        DynamicModelSelectionStrategy strategy = new DynamicModelSelectionStrategy(modelRegistry, properties, null);
        when(modelRegistry.getModel("missing-model")).thenThrow(new IllegalStateException("missing"));
        when(modelRegistry.getModel("tier-model")).thenThrow(new IllegalStateException("missing"));

        assertThat(strategy.selectModel(ExecutionContext.builder().preferredModel("missing-model").tier(1).build())).isNull();

        assertThat(alarms()).singleElement().satisfies(alarm -> {
            assertThat(alarm.getLevel()).isEqualTo(Level.ERROR);
            assertThat(alarm.getFormattedMessage()).contains("No model available", "missing-model", "tier-model");
        });
    }

    /**
     * The primary chat model is the designed path when no model was asked for and no tier model is set, so it is no
     * fallback; its provider comes from the chat model itself when the registry does not describe its model.
     */
    @Test
    void thePrimaryModelWithoutARequestIsNoFallbackAndNamesItsProvider() {
        ChatModel anthropic = AnthropicChatModel.builder()
                .anthropicApi(AnthropicApi.builder().apiKey("test").build())
                .defaultOptions(AnthropicChatOptions.builder().model("claude-haiku-5-5").build())
                .build();
        DynamicModelSelectionStrategy strategy = new DynamicModelSelectionStrategy(modelRegistry,
                new TieredLLMProperties(), anthropic);
        ExecutionContext context = ExecutionContext.builder().prompt(new Prompt("security prompt")).build();

        assertThat(strategy.selectModel(context)).isSameAs(anthropic);
        assertThat(context.getMetadata())
                .containsEntry("selectedModelId", "claude-haiku-5-5")
                .containsEntry("selectedModelProvider", "anthropic")
                .containsEntry("modelSelectionFallbackUsed", false);
    }

    @Test
    void selectModelShouldPreferExplicitRequestedModelBeforeTier() {
        TieredLLMProperties properties = new TieredLLMProperties();
        properties.getLayer1().setModel("tier-model");
        DynamicModelSelectionStrategy strategy = new DynamicModelSelectionStrategy(modelRegistry, properties, primaryChatModel);

        when(modelRegistry.getModel("client-model")).thenReturn(explicitModel);
        when(modelRegistry.getDescriptor("client-model")).thenReturn(ModelDescriptor.builder()
                .modelId("client-model")
                .provider("ollama")
                .build());

        ExecutionContext context = ExecutionContext.builder()
                .preferredModel("client-model")
                .tier(1)
                .build();

        ChatModel selected = strategy.selectModel(context);

        assertThat(selected).isSameAs(explicitModel);
        assertThat(context.getMetadata())
                .containsEntry("requestedModelId", "client-model")
                .containsEntry("requestedModelSourceKey", "executionContext.preferredModel")
                .containsEntry("selectedModelId", "client-model")
                .containsEntry("runtimeModelId", "client-model")
                .containsEntry("selectedModelProvider", "ollama")
                .containsEntry("modelSelectionSource", "explicit_model")
                .containsEntry("modelSelectionFallbackUsed", false);
        verify(modelRegistry).getModel("client-model");
        verify(modelRegistry, never()).getModel("tier-model");
    }

    @Test
    void selectModelShouldFallbackToTierWhenExplicitRequestedModelIsUnavailable() {
        TieredLLMProperties properties = new TieredLLMProperties();
        properties.getLayer1().setModel("tier-model");
        DynamicModelSelectionStrategy strategy = new DynamicModelSelectionStrategy(modelRegistry, properties, primaryChatModel);

        when(modelRegistry.getModel("missing-model")).thenThrow(new IllegalStateException("missing"));
        when(modelRegistry.getModel("tier-model")).thenReturn(tierModel);
        when(modelRegistry.getDescriptor("tier-model")).thenReturn(ModelDescriptor.builder()
                .modelId("tier-model")
                .provider("openai")
                .build());

        ExecutionContext context = ExecutionContext.builder()
                .preferredModel("missing-model")
                .tier(1)
                .build();

        ChatModel selected = strategy.selectModel(context);

        assertThat(selected).isSameAs(tierModel);
        assertThat(context.getMetadata())
                .containsEntry("requestedModelId", "missing-model")
                .containsEntry("selectedModelId", "tier-model")
                .containsEntry("runtimeModelId", "tier-model")
                .containsEntry("selectedModelProvider", "openai")
                .containsEntry("modelSelectionSource", "tier:1")
                .containsEntry("modelSelectionFallbackUsed", true)
                .containsEntry("modelSelectionFailure", "Requested model not available: missing-model");
    }
}
