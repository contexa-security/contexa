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
package io.contexa.autoconfigure.core.llm.runtime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import io.contexa.autoconfigure.properties.ContexaLlmBindingProperties;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeBinding;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.mock.env.MockEnvironment;

class SpringLlmRuntimeCatalogTest {

    @Test
    void shouldNotTouchLowerPriorityProviderWhenHigherPriorityBindingResolves() {
        ConfigurableApplicationContext applicationContext = mock(ConfigurableApplicationContext.class);
        ConfigurableListableBeanFactory beanFactory = mock(ConfigurableListableBeanFactory.class);
        BeanDefinition ollamaDefinition = mock(BeanDefinition.class);
        BeanDefinition openAiDefinition = mock(BeanDefinition.class);
        when(applicationContext.getBeanFactory()).thenReturn(beanFactory);
        when(beanFactory.getBeanNamesForType(ChatModel.class, true, false)).thenReturn(new String[]{"ollamaChatModel", "openAiChatModel"});
        when(beanFactory.getBeanNamesForType(EmbeddingModel.class, true, false)).thenReturn(new String[0]);
        Mockito.doReturn((Class<?>) OllamaRuntimeStub.class).when(beanFactory).getType("ollamaChatModel", false);
        Mockito.doReturn((Class<?>) OpenAiRuntimeStub.class).when(beanFactory).getType("openAiChatModel", false);
        when(beanFactory.containsBeanDefinition("ollamaChatModel")).thenReturn(true);
        when(beanFactory.containsBeanDefinition("openAiChatModel")).thenReturn(true);
        when(beanFactory.getBeanDefinition("ollamaChatModel")).thenReturn(ollamaDefinition);
        when(beanFactory.getBeanDefinition("openAiChatModel")).thenReturn(openAiDefinition);
        when(ollamaDefinition.isPrimary()).thenReturn(false);
        when(openAiDefinition.isPrimary()).thenReturn(false);

        ChatModel ollamaChatModel = mock(ChatModel.class);
        when(applicationContext.getBean("ollamaChatModel", ChatModel.class)).thenReturn(ollamaChatModel);
        when(applicationContext.getBean("openAiChatModel", ChatModel.class)).thenThrow(new IllegalStateException("should not touch openai"));

        ContexaProperties properties = new ContexaProperties();
        ContexaLlmBindingProperties bindingProperties = new ContexaLlmBindingProperties();
        SpringLlmRuntimeCatalog catalog = new SpringLlmRuntimeCatalog(applicationContext, properties, bindingProperties);

        Optional<ChatModel> resolved = catalog.resolvePrimaryChatModel("ollama,openai");

        assertThat(resolved).containsSame(ollamaChatModel);
        verify(applicationContext, never()).getBean("openAiChatModel", ChatModel.class);
    }

    @Test
    void shouldExposeSpringOpenAiConfiguredModelsAsBindingIds() {
        ConfigurableApplicationContext applicationContext = mock(ConfigurableApplicationContext.class);
        ConfigurableListableBeanFactory beanFactory = mock(ConfigurableListableBeanFactory.class);
        when(applicationContext.getBeanFactory()).thenReturn(beanFactory);
        when(applicationContext.getEnvironment()).thenReturn(new MockEnvironment()
                .withProperty("spring.ai.openai.chat.options.model", "gpt-5-nano")
                .withProperty("spring.ai.openai.embedding.options.model", "text-embedding-3-small"));
        when(beanFactory.getBeanNamesForType(ChatModel.class, true, false)).thenReturn(new String[]{"openAiChatModel"});
        when(beanFactory.getBeanNamesForType(EmbeddingModel.class, true, false)).thenReturn(new String[]{"openAiEmbeddingModel"});
        Mockito.doReturn((Class<?>) OpenAiRuntimeStub.class).when(beanFactory).getType("openAiChatModel", false);
        Mockito.doReturn((Class<?>) OpenAiRuntimeStub.class).when(beanFactory).getType("openAiEmbeddingModel", false);
        when(beanFactory.containsBeanDefinition("openAiChatModel")).thenReturn(false);
        when(beanFactory.containsBeanDefinition("openAiEmbeddingModel")).thenReturn(false);

        SpringLlmRuntimeCatalog catalog = new SpringLlmRuntimeCatalog(
                applicationContext,
                new ContexaProperties(),
                new ContexaLlmBindingProperties());

        LlmRuntimeBinding chatBinding = catalog.findChatBinding("gpt-5-nano").orElseThrow();
        LlmRuntimeBinding embeddingBinding = catalog.findEmbeddingBinding("text-embedding-3-small").orElseThrow();

        assertThat(chatBinding.getProvider()).isEqualTo("openai");
        assertThat(chatBinding.getModelId()).isEqualTo("gpt-5-nano");
        assertThat(embeddingBinding.getProvider()).isEqualTo("openai");
        assertThat(embeddingBinding.getModelId()).isEqualTo("text-embedding-3-small");
    }
    @Test
    void shouldExposeConfiguredAliasBinding() {
        ConfigurableApplicationContext applicationContext = mock(ConfigurableApplicationContext.class);
        ConfigurableListableBeanFactory beanFactory = mock(ConfigurableListableBeanFactory.class);
        BeanDefinition geminiDefinition = mock(BeanDefinition.class);
        when(applicationContext.getBeanFactory()).thenReturn(beanFactory);
        when(beanFactory.getBeanNamesForType(ChatModel.class, true, false)).thenReturn(new String[]{"geminiChatModel"});
        when(beanFactory.getBeanNamesForType(EmbeddingModel.class, true, false)).thenReturn(new String[0]);
        Mockito.doReturn((Class<?>) ChatModel.class).when(beanFactory).getType("geminiChatModel", false);
        when(beanFactory.containsBeanDefinition("geminiChatModel")).thenReturn(true);
        when(beanFactory.getBeanDefinition("geminiChatModel")).thenReturn(geminiDefinition);
        when(geminiDefinition.isPrimary()).thenReturn(true);

        ContexaProperties properties = new ContexaProperties();
        ContexaLlmBindingProperties bindingProperties = new ContexaLlmBindingProperties();
        ContexaLlmBindingProperties.Binding binding = new ContexaLlmBindingProperties.Binding();
        binding.setBeanName("geminiChatModel");
        binding.setProvider("gemini");
        binding.setModelId("gemini-2.5-pro");
        binding.setAliases(List.of("gemini-pro", "gemini-main"));
        bindingProperties.getChat().put("geminiMain", binding);

        SpringLlmRuntimeCatalog catalog = new SpringLlmRuntimeCatalog(applicationContext, properties, bindingProperties);

        LlmRuntimeBinding resolved = catalog.findChatBinding("gemini-pro").orElseThrow();

        assertThat(resolved.getBeanName()).isEqualTo("geminiChatModel");
        assertThat(resolved.getProvider()).isEqualTo("gemini");
        assertThat(resolved.getModelId()).isEqualTo("gemini-2.5-pro");
        assertThat(resolved.isPrimary()).isTrue();
    }

    @Test
    void shouldFailFastWhenChatSelectorsCollideAcrossBindings() {
        ConfigurableApplicationContext applicationContext = mock(ConfigurableApplicationContext.class);
        ConfigurableListableBeanFactory beanFactory = mock(ConfigurableListableBeanFactory.class);
        BeanDefinition geminiDefinition = mock(BeanDefinition.class);
        BeanDefinition vertexDefinition = mock(BeanDefinition.class);
        when(applicationContext.getBeanFactory()).thenReturn(beanFactory);
        when(beanFactory.getBeanNamesForType(ChatModel.class, true, false)).thenReturn(new String[]{"geminiChatModel", "vertexChatModel"});
        when(beanFactory.getBeanNamesForType(EmbeddingModel.class, true, false)).thenReturn(new String[0]);
        Mockito.doReturn((Class<?>) GeminiRuntimeStub.class).when(beanFactory).getType("geminiChatModel", false);
        Mockito.doReturn((Class<?>) VertexRuntimeStub.class).when(beanFactory).getType("vertexChatModel", false);
        when(beanFactory.containsBeanDefinition("geminiChatModel")).thenReturn(true);
        when(beanFactory.containsBeanDefinition("vertexChatModel")).thenReturn(true);
        when(beanFactory.getBeanDefinition("geminiChatModel")).thenReturn(geminiDefinition);
        when(beanFactory.getBeanDefinition("vertexChatModel")).thenReturn(vertexDefinition);
        when(geminiDefinition.isPrimary()).thenReturn(false);
        when(vertexDefinition.isPrimary()).thenReturn(false);

        ContexaLlmBindingProperties bindingProperties = new ContexaLlmBindingProperties();
        ContexaLlmBindingProperties.Binding geminiBinding = new ContexaLlmBindingProperties.Binding();
        geminiBinding.setBeanName("geminiChatModel");
        geminiBinding.setProvider("gemini");
        geminiBinding.setAliases(List.of("shared-alias"));
        bindingProperties.getChat().put("geminiMain", geminiBinding);

        ContexaLlmBindingProperties.Binding vertexBinding = new ContexaLlmBindingProperties.Binding();
        vertexBinding.setBeanName("vertexChatModel");
        vertexBinding.setProvider("vertex");
        vertexBinding.setAliases(List.of("shared-alias"));
        bindingProperties.getChat().put("vertexMain", vertexBinding);

        SpringLlmRuntimeCatalog catalog = new SpringLlmRuntimeCatalog(applicationContext, new ContexaProperties(), bindingProperties);

        assertThatThrownBy(catalog::getChatBindings)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Duplicate chat runtime selector 'shared-alias'");
    }

    @Test
    void shouldResolveSpringPrimaryChatModelWhenExactlyOneBindingIsPrimary() {
        ConfigurableApplicationContext applicationContext = mock(ConfigurableApplicationContext.class);
        ConfigurableListableBeanFactory beanFactory = mock(ConfigurableListableBeanFactory.class);
        BeanDefinition ollamaDefinition = mock(BeanDefinition.class);
        BeanDefinition openAiDefinition = mock(BeanDefinition.class);
        when(applicationContext.getBeanFactory()).thenReturn(beanFactory);
        when(beanFactory.getBeanNamesForType(ChatModel.class, true, false)).thenReturn(new String[]{"ollamaChatModel", "openAiChatModel"});
        when(beanFactory.getBeanNamesForType(EmbeddingModel.class, true, false)).thenReturn(new String[0]);
        Mockito.doReturn((Class<?>) OllamaRuntimeStub.class).when(beanFactory).getType("ollamaChatModel", false);
        Mockito.doReturn((Class<?>) OpenAiRuntimeStub.class).when(beanFactory).getType("openAiChatModel", false);
        when(beanFactory.containsBeanDefinition("ollamaChatModel")).thenReturn(true);
        when(beanFactory.containsBeanDefinition("openAiChatModel")).thenReturn(true);
        when(beanFactory.getBeanDefinition("ollamaChatModel")).thenReturn(ollamaDefinition);
        when(beanFactory.getBeanDefinition("openAiChatModel")).thenReturn(openAiDefinition);
        when(ollamaDefinition.isPrimary()).thenReturn(true);
        when(openAiDefinition.isPrimary()).thenReturn(false);

        ChatModel ollamaChatModel = mock(ChatModel.class);
        when(applicationContext.getBean("ollamaChatModel", ChatModel.class)).thenReturn(ollamaChatModel);

        SpringLlmRuntimeCatalog catalog = new SpringLlmRuntimeCatalog(applicationContext, new ContexaProperties(), new ContexaLlmBindingProperties());

        assertThat(catalog.resolveSpringPrimaryChatModel()).containsSame(ollamaChatModel);
        verify(applicationContext, never()).getBean("openAiChatModel", ChatModel.class);
    }

    @Test
    void shouldFailFastWhenSpringPrimaryChatSelectionIsAmbiguous() {
        ConfigurableApplicationContext applicationContext = mock(ConfigurableApplicationContext.class);
        ConfigurableListableBeanFactory beanFactory = mock(ConfigurableListableBeanFactory.class);
        BeanDefinition ollamaDefinition = mock(BeanDefinition.class);
        BeanDefinition openAiDefinition = mock(BeanDefinition.class);
        when(applicationContext.getBeanFactory()).thenReturn(beanFactory);
        when(beanFactory.getBeanNamesForType(ChatModel.class, true, false)).thenReturn(new String[]{"ollamaChatModel", "openAiChatModel"});
        when(beanFactory.getBeanNamesForType(EmbeddingModel.class, true, false)).thenReturn(new String[0]);
        Mockito.doReturn((Class<?>) OllamaRuntimeStub.class).when(beanFactory).getType("ollamaChatModel", false);
        Mockito.doReturn((Class<?>) OpenAiRuntimeStub.class).when(beanFactory).getType("openAiChatModel", false);
        when(beanFactory.containsBeanDefinition("ollamaChatModel")).thenReturn(true);
        when(beanFactory.containsBeanDefinition("openAiChatModel")).thenReturn(true);
        when(beanFactory.getBeanDefinition("ollamaChatModel")).thenReturn(ollamaDefinition);
        when(beanFactory.getBeanDefinition("openAiChatModel")).thenReturn(openAiDefinition);
        when(ollamaDefinition.isPrimary()).thenReturn(false);
        when(openAiDefinition.isPrimary()).thenReturn(false);

        SpringLlmRuntimeCatalog catalog = new SpringLlmRuntimeCatalog(applicationContext, new ContexaProperties(), new ContexaLlmBindingProperties());

        assertThatThrownBy(catalog::resolveSpringPrimaryChatModel)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("none is marked primary")
                .hasMessageContaining("contexa.llm.selection.chat.mode=dynamic-priority");
    }

    private static final class OllamaRuntimeStub {
    }

    private static final class OpenAiRuntimeStub {
    }

    private static final class GeminiRuntimeStub {
    }

    private static final class VertexRuntimeStub {
    }
}
