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
package io.contexa.autoconfigure.core.llm;

import io.contexa.autoconfigure.properties.ContexaLlmSelectionProperties;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.llm.handler.StreamingHandler;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeCatalog;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CoreLLMTieredAutoConfigurationProviderResolutionTest {

    @Test
    void shouldResolveDynamicPriorityPrimaryChatModelThroughRuntimeCatalog() {
        CoreLLMTieredAutoConfiguration configuration = new CoreLLMTieredAutoConfiguration();
        ContexaProperties properties = new ContexaProperties();
        properties.getLlm().setChatModelPriority("openai,anthropic");
        ReflectionTestUtils.setField(configuration, "contexaProperties", properties);
        ContexaLlmSelectionProperties selectionProperties = new ContexaLlmSelectionProperties();
        selectionProperties.getChat().setPriority("openai,anthropic");
        ReflectionTestUtils.setField(configuration, "contexaLlmSelectionProperties", selectionProperties);

        LlmRuntimeCatalog catalog = mock(LlmRuntimeCatalog.class);
        ChatModel selectedModel = mock(ChatModel.class);
        when(catalog.resolvePrimaryChatModel("openai,anthropic")).thenReturn(Optional.of(selectedModel));

        ChatModel resolved = configuration.dynamicPriorityPrimaryChatModel(catalog);

        assertThat(resolved).isSameAs(selectedModel);
        verify(catalog).resolvePrimaryChatModel("openai,anthropic");
    }

    @Test
    void shouldPreferSelectionPriorityOverLegacyChatModelPriority() {
        CoreLLMTieredAutoConfiguration configuration = new CoreLLMTieredAutoConfiguration();
        ContexaProperties properties = new ContexaProperties();
        properties.getLlm().setChatModelPriority("legacy-openai,legacy-ollama");
        ReflectionTestUtils.setField(configuration, "contexaProperties", properties);
        ContexaLlmSelectionProperties selectionProperties = new ContexaLlmSelectionProperties();
        selectionProperties.getChat().setPriority("gemini,openai");
        ReflectionTestUtils.setField(configuration, "contexaLlmSelectionProperties", selectionProperties);

        LlmRuntimeCatalog catalog = mock(LlmRuntimeCatalog.class);
        ChatModel selectedModel = mock(ChatModel.class);
        when(catalog.resolvePrimaryChatModel("gemini,openai")).thenReturn(Optional.of(selectedModel));

        ChatModel resolved = configuration.dynamicPriorityPrimaryChatModel(catalog);

        assertThat(resolved).isSameAs(selectedModel);
        verify(catalog).resolvePrimaryChatModel("gemini,openai");
    }

    @Test
    void shouldFailFastWithProviderConfigurationMessageWhenNoChatModelSelectionStrategyExists() {
        CoreLLMTieredAutoConfiguration configuration = new CoreLLMTieredAutoConfiguration();
        ReflectionTestUtils.setField(configuration, "contexaProperties", new ContexaProperties());
        ReflectionTestUtils.setField(configuration, "contexaLlmSelectionProperties", new ContexaLlmSelectionProperties());
        ReflectionTestUtils.setField(configuration, "tieredLLMProperties", new TieredLLMProperties());

        StaticListableBeanFactory beanFactory = new StaticListableBeanFactory();
        AdvisorRegistry advisorRegistry = mock(AdvisorRegistry.class);
        StreamingHandler streamingHandler = mock(StreamingHandler.class);

        assertThatThrownBy(() -> configuration.unifiedLLMOrchestrator(
                beanFactory.getBeanProvider(ModelSelectionStrategy.class),
                streamingHandler,
                advisorRegistry,
                beanFactory.getBeanProvider(ChatClient.class)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No Spring AI ChatModel is configured for CONTEXA")
                .hasMessageContaining("spring-ai-starter-model-openai")
                .hasMessageContaining("spring.ai.openai.*")
                .hasMessageContaining("ChatModel bean");
    }

    @Test
    void shouldResolveSpringPrimaryChatModelThroughDedicatedCatalogPath() {
        CoreLLMTieredAutoConfiguration configuration = new CoreLLMTieredAutoConfiguration();
        ReflectionTestUtils.setField(configuration, "contexaProperties", new ContexaProperties());
        ContexaLlmSelectionProperties selectionProperties = new ContexaLlmSelectionProperties();
        selectionProperties.getChat().setMode(ContexaLlmSelectionProperties.Mode.SPRING_PRIMARY);
        ReflectionTestUtils.setField(configuration, "contexaLlmSelectionProperties", selectionProperties);

        LlmRuntimeCatalog catalog = mock(LlmRuntimeCatalog.class);
        ChatModel selectedModel = mock(ChatModel.class);
        when(catalog.resolveSpringPrimaryChatModel()).thenReturn(Optional.of(selectedModel));

        ChatModel resolved = configuration.springPrimaryChatModel(catalog);

        assertThat(resolved).isSameAs(selectedModel);
        verify(catalog).resolveSpringPrimaryChatModel();
    }
}
