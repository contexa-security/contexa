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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.RootBeanDefinition;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * An application that chose its default model ({@code @Primary}) and Contexa, whose own models are {@code @Primary} too, are two primaries
 * for Spring ("more than one 'primary' bean found"): the application did not start (found by the hostile host).
 */
class HostPrimaryModelStandAsideTest {

    private static <T> void register(DefaultListableBeanFactory factory, String name, Class<T> type, T instance, boolean primary) {
        RootBeanDefinition definition = new RootBeanDefinition(type, () -> instance);
        definition.setPrimary(primary);
        factory.registerBeanDefinition(name, definition);
    }

    @Test
    @DisplayName("control: without the post processor two primary models do not start")
    void twoPrimaryModelsDoNotResolve() {
        DefaultListableBeanFactory factory = new DefaultListableBeanFactory();
        register(factory, "hostChatModel", ChatModel.class, mock(ChatModel.class), true);
        register(factory, "contexaPrimaryChatModel", ChatModel.class, mock(ChatModel.class), true);

        assertThatThrownBy(() -> factory.getBean(ChatModel.class)).isInstanceOf(NoUniqueBeanDefinitionException.class);
    }

    @Test
    @DisplayName("the application's primary model stands, Contexa's primary models stand aside")
    void theApplicationsPrimaryModelIsTheOneResolved() {
        DefaultListableBeanFactory factory = new DefaultListableBeanFactory();
        ChatModel host = mock(ChatModel.class);
        register(factory, "hostChatModel", ChatModel.class, host, true);
        register(factory, "anthropicChatModel", ChatModel.class, mock(ChatModel.class), false);
        register(factory, "contexaPrimaryChatModel", ChatModel.class, mock(ChatModel.class), true);
        EmbeddingModel hostEmbedding = mock(EmbeddingModel.class);
        register(factory, "hostEmbeddingModel", EmbeddingModel.class, hostEmbedding, true);
        register(factory, "contexaPrimaryEmbeddingModel", EmbeddingModel.class, mock(EmbeddingModel.class), true);

        new HostPrimaryModelStandAside().postProcessBeanFactory(factory);

        assertThat(factory.getBean(ChatModel.class)).isSameAs(host);
        assertThat(factory.getBean(EmbeddingModel.class)).isSameAs(hostEmbedding);
        assertThat(factory.getBeanDefinition("contexaPrimaryChatModel").isPrimary()).isFalse();
        assertThat(factory.getBeanDefinition("hostChatModel").isPrimary()).isTrue();
    }

    @Test
    @DisplayName("an application without a primary model of its own is not touched")
    void withoutAPrimaryOfItsOwnContexasStayPrimary() {
        DefaultListableBeanFactory factory = new DefaultListableBeanFactory();
        ChatModel contexa = mock(ChatModel.class);
        register(factory, "anthropicChatModel", ChatModel.class, mock(ChatModel.class), false);
        register(factory, "contexaPrimaryChatModel", ChatModel.class, contexa, true);

        new HostPrimaryModelStandAside().postProcessBeanFactory(factory);

        assertThat(factory.getBeanDefinition("contexaPrimaryChatModel").isPrimary()).isTrue();
        assertThat(factory.getBean(ChatModel.class)).isSameAs(contexa);
    }

    @Test
    @DisplayName("an application with only a primary model of its own and no Contexa model is not touched")
    void withoutContexasModelNothingChanges() {
        DefaultListableBeanFactory factory = new DefaultListableBeanFactory();
        ChatModel host = mock(ChatModel.class);
        register(factory, "hostChatModel", ChatModel.class, host, true);

        new HostPrimaryModelStandAside().postProcessBeanFactory(factory);

        assertThat(factory.getBean(ChatModel.class)).isSameAs(host);
        assertThat(factory.getBeanDefinition("hostChatModel").isPrimary()).isTrue();
    }
}
