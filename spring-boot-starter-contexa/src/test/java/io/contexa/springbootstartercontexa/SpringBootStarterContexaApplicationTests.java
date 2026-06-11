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
package io.contexa.springbootstartercontexa;

import io.contexa.autoconfigure.core.llm.CoreLLMTieredAutoConfiguration;
import io.contexa.autoconfigure.core.llm.runtime.SpringLlmRuntimeCatalog;
import io.contexa.autoconfigure.properties.ContexaLlmBindingProperties;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeCatalog;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import io.contexa.contexacore.std.pipeline.streaming.JsonStreamingProcessor;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.util.ClassUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class SpringBootStarterContexaApplicationTests {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(CoreLLMTieredAutoConfiguration.class))
            .withUserConfiguration(TestConfiguration.class)
            .withPropertyValues(
                    "contexa.llm.selection.chat.mode=spring-primary",
                    "contexa.llm.selection.embedding.mode=spring-primary"
            );

    @Test
    void contextLoadsWithSpringAiStandardRuntimeBeans() {
        contextRunner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasBean("standardChatModel");
            assertThat(context).hasBean("standardEmbeddingModel");
            assertThat(context).hasBean("primaryChatModel");
            assertThat(context).hasBean("primaryEmbeddingModel");
            assertThat(context.getBean(ChatModel.class)).isSameAs(context.getBean("standardChatModel"));
            assertThat(context.getBean(ChatModel.class)).isSameAs(context.getBean("primaryChatModel"));
            assertThat(context.getBean(EmbeddingModel.class)).isSameAs(context.getBean("standardEmbeddingModel"));
            assertThat(context.getBean(EmbeddingModel.class)).isSameAs(context.getBean("primaryEmbeddingModel"));
            assertThat(context.getBean(LlmRuntimeCatalog.class).getChatBindings()).hasSize(1);
            assertThat(context.getBean(LlmRuntimeCatalog.class).getEmbeddingBindings()).hasSize(1);
        });
    }

    @Test
    void starterDoesNotExposePgVectorAutoConfiguration() {
        ClassLoader classLoader = getClass().getClassLoader();

        assertThat(ClassUtils.isPresent(
                "org.springframework.ai.vectorstore.pgvector.PgVectorStore",
                classLoader)).isTrue();
        assertThat(ClassUtils.isPresent(
                "org.springframework.ai.vectorstore.pgvector.autoconfigure.PgVectorStoreAutoConfiguration",
                classLoader)).isFalse();
    }

    @Test
    void starterDoesNotExposeMcpClientAutoConfiguration() {
        ClassLoader classLoader = getClass().getClassLoader();

        assertThat(ClassUtils.isPresent(
                "org.springframework.ai.mcp.client.common.autoconfigure.McpClientAutoConfiguration",
                classLoader)).isFalse();
        assertThat(ClassUtils.isPresent(
                "org.springframework.ai.mcp.client.httpclient.autoconfigure.SseHttpClientTransportAutoConfiguration",
                classLoader)).isFalse();
    }

    @Configuration(proxyBeanMethods = false)
    static class TestConfiguration {

        @Bean
        ContexaProperties contexaProperties() {
            return new ContexaProperties();
        }

        @Bean
        ContexaLlmBindingProperties contexaLlmBindingProperties() {
            return new ContexaLlmBindingProperties();
        }

        @Bean
        AdvisorRegistry advisorRegistry() {
            return new AdvisorRegistry();
        }

        @Bean
        JsonStreamingProcessor jsonStreamingProcessor() {
            return mock(JsonStreamingProcessor.class);
        }

        @Bean
        ModelSelectionStrategy modelSelectionStrategy() {
            return mock(ModelSelectionStrategy.class);
        }

        @Bean
        PlatformConfig platformConfig() {
            return PlatformConfig.builder().build();
        }

        @Bean
        LlmRuntimeCatalog llmRuntimeCatalog(
                ConfigurableApplicationContext applicationContext,
                ContexaProperties contexaProperties,
                ContexaLlmBindingProperties contexaLlmBindingProperties) {
            return new SpringLlmRuntimeCatalog(applicationContext, contexaProperties, contexaLlmBindingProperties);
        }

        @Bean
        @Primary
        ChatModel standardChatModel() {
            return mock(ChatModel.class);
        }

        @Bean
        @Primary
        EmbeddingModel standardEmbeddingModel() {
            return mock(EmbeddingModel.class);
        }
    }
}
