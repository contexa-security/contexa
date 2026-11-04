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
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Contexa's chat model, embedding model and chat client builder are its own beans and no default candidates: an application that uses Spring AI keeps
 * its own models and its own builder (found by the hostile host: with Contexa the application's {@code EmbeddingModel} and {@code ChatClient.Builder}
 * injections were given Contexa's wrappers, and an application with a primary model of its own did not start). Contexa's code names its beans.
 */
class SpringAiWrappersHostCoexistenceTest {

    private final ApplicationContextRunner contexts = new ApplicationContextRunner().withUserConfiguration(TheApplication.class, ContexasWrappers.class);

    @Configuration(proxyBeanMethods = false)
    static class TheApplication {

        @Bean
        ChatModel anthropicChatModel() {
            return mock(ChatModel.class);
        }

        @Bean
        EmbeddingModel ollamaEmbeddingModel() {
            return mock(EmbeddingModel.class);
        }

        /** What Spring AI's own auto-configuration does: a builder of the application's model, only when no builder is there. */
        @Bean
        @ConditionalOnMissingBean(ChatClient.Builder.class)
        ChatClient.Builder chatClientBuilder(ChatModel chatModel) {
            return ChatClient.builder(chatModel);
        }
    }

    /** The shape of Contexa's beans: named, not default candidates. */
    @Configuration(proxyBeanMethods = false)
    static class ContexasWrappers {

        @Bean(name = "contexaPrimaryChatModel", defaultCandidate = false)
        ChatModel contexaPrimaryChatModel() {
            return mock(ChatModel.class);
        }

        @Bean(name = {"contexaPrimaryEmbeddingModel", "contexaEmbeddingModel"}, defaultCandidate = false)
        EmbeddingModel contexaPrimaryEmbeddingModel() {
            return mock(EmbeddingModel.class);
        }

        @Bean(name = "contexaChatClientBuilder", defaultCandidate = false)
        ChatClient.Builder contexaChatClientBuilder(@Qualifier("contexaPrimaryChatModel") ChatModel model) {
            return ChatClient.builder(model);
        }

        @Bean
        ContexasEngine contexasEngine(@Qualifier("contexaPrimaryChatModel") ChatModel chat,
                                      @Qualifier("contexaPrimaryEmbeddingModel") EmbeddingModel embedding,
                                      @Qualifier("contexaChatClientBuilder") ChatClient.Builder builder) {
            return new ContexasEngine(chat, embedding, builder);
        }
    }

    record ContexasEngine(ChatModel chat, EmbeddingModel embedding, ChatClient.Builder builder) {
    }

    @Configuration(proxyBeanMethods = false)
    static class AnApplicationWithAPrimaryModel {

        @Bean
        @Primary
        ChatModel hostChatModel() {
            return mock(ChatModel.class);
        }
    }

    record ApplicationsService(ChatModel chat, EmbeddingModel embedding, ChatClient.Builder builder) {
    }

    @Configuration(proxyBeanMethods = false)
    static class ApplicationsInjectionPoints {

        @Bean
        ApplicationsService applicationsService(ChatModel chat, EmbeddingModel embedding, ChatClient.Builder builder) {
            return new ApplicationsService(chat, embedding, builder);
        }
    }

    @Test
    @DisplayName("the application's injection by type gets the application's models and builder, not Contexa's wrappers")
    void theApplicationGetsItsOwnBeans() {
        contexts.withUserConfiguration(ApplicationsInjectionPoints.class).run(context -> {
            assertThat(context).hasNotFailed();
            ApplicationsService service = context.getBean(ApplicationsService.class);
            assertThat(service.chat()).isSameAs(context.getBean("anthropicChatModel"));
            assertThat(service.embedding()).isSameAs(context.getBean("ollamaEmbeddingModel"));
            assertThat(service.builder()).as("the application's builder of Spring AI, made next to Contexa's").isNotSameAs(context.getBean("contexaChatClientBuilder"));
        });
    }

    @Test
    @DisplayName("Contexa's engine, which names its beans, gets its wrappers")
    void contexasEngineGetsItsOwnBeans() {
        contexts.run(context -> {
            ContexasEngine engine = context.getBean(ContexasEngine.class);
            assertThat(engine.chat()).isSameAs(context.getBean("contexaPrimaryChatModel"));
            assertThat(engine.embedding()).isSameAs(context.getBean("contexaPrimaryEmbeddingModel"));
            assertThat(engine.builder()).isSameAs(context.getBean("contexaChatClientBuilder"));
        });
    }

    @Test
    @DisplayName("an application with a primary model of its own starts: Contexa's models are no second primary")
    void anApplicationWithAPrimaryModelStarts() {
        contexts.withUserConfiguration(AnApplicationWithAPrimaryModel.class, ApplicationsInjectionPoints.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(ApplicationsService.class).chat()).isSameAs(context.getBean("hostChatModel"));
            assertThat(context.getBean(ContexasEngine.class).chat()).isSameAs(context.getBean("contexaPrimaryChatModel"));
        });
    }

    @Test
    @DisplayName("control: the same wrappers as default candidates take the application's injection and a second primary stops it")
    void controlDefaultCandidatesAreTakenByTheApplication() {
        new ApplicationContextRunner().withUserConfiguration(TheApplication.class, DefaultCandidateWrappers.class,
                ApplicationsInjectionPoints.class).run(context -> {
            // two default models and no primary: the application's own injection does not even resolve
            assertThat(context).hasFailed();
        });
    }

    @Configuration(proxyBeanMethods = false)
    static class DefaultCandidateWrappers {

        @Bean(name = "contexaPrimaryChatModel")
        ChatModel contexaPrimaryChatModel() {
            return mock(ChatModel.class);
        }
    }
}
