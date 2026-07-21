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
package io.contexa.autoconfigure.compat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.io.support.SpringFactoriesLoader;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.core.io.ByteArrayResource;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class ContexaDefaultPropertiesPostProcessorTest {

    private final ContexaDefaultPropertiesPostProcessor postProcessor = new ContexaDefaultPropertiesPostProcessor();

    @Test
    @DisplayName("is registered in the Spring Boot environment post-processor factory")
    void isRegisteredInSpringBootFactory() {
        var processorNames = SpringFactoriesLoader.loadFactoryNames(
                EnvironmentPostProcessor.class,
                getClass().getClassLoader());

        assertThat(processorNames)
                .contains(ContexaDefaultPropertiesPostProcessor.class.getName());
    }

    @Test
    @DisplayName("injects zero-configuration 1024-dimension vector and OpenAI embedding defaults")
    void injectsZeroConfigurationDefaults() {
        MockEnvironment environment = new MockEnvironment();

        postProcessor.postProcessEnvironment(environment, new SpringApplication());

        assertThat(environment.getProperty("contexa.vectorstore.pgvector.dimensions")).isEqualTo("1024");
        assertThat(environment.getProperty("spring.ai.vectorstore.pgvector.dimensions")).isEqualTo("1024");
        assertThat(environment.getProperty("spring.ai.vectorstore.pgvector.initialize-schema")).isEqualTo("true");
        assertThat(environment.getProperty("spring.ai.vectorstore.pgvector.schema-name")).isEqualTo("public");
        assertThat(environment.getProperty("spring.ai.vectorstore.pgvector.table-name")).isEqualTo("vector_store");
        assertThat(environment.getProperty("spring.ai.openai.embedding.options.model")).isEqualTo("text-embedding-3-small");
        assertThat(environment.getProperty("spring.ai.openai.embedding.options.dimensions")).isEqualTo("1024");
        assertThat(environment.getProperty("contexa.llm.selection.embedding.mode")).isNull();
        assertThat(environment.getProperty("contexa.llm.selection.embedding.priority")).isNull();
        assertThat(environment.getProperty("spring.ai.model.chat")).isNull();
        assertThat(environment.getProperty("spring.ai.model.embedding")).isNull();
    }

    @Test
    @DisplayName("does not override explicit user properties")
    void doesNotOverrideExplicitUserProperties() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("spring.ai.vectorstore.pgvector.dimensions", "2048")
                .withProperty("spring.ai.openai.embedding.options.dimensions", "2048");

        postProcessor.postProcessEnvironment(environment, new SpringApplication());

        assertThat(environment.getProperty("spring.ai.vectorstore.pgvector.dimensions")).isEqualTo("2048");
        assertThat(environment.getProperty("spring.ai.openai.embedding.options.dimensions")).isEqualTo("2048");
        assertThat(environment.getPropertySources().contains(ContexaDefaultPropertiesPostProcessor.SOURCE_NAME)).isTrue();
    }

    @Test
    @DisplayName("aligns default OpenAI embedding dimensions with explicit vector-store dimensions")
    void alignsOpenAiDimensionsWithExplicitVectorStoreDimensions() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("contexa.vectorstore.pgvector.dimensions", "1536");

        postProcessor.postProcessEnvironment(environment, new SpringApplication());

        assertThat(environment.getProperty("contexa.vectorstore.pgvector.dimensions")).isEqualTo("1536");
        assertThat(environment.getProperty("spring.ai.vectorstore.pgvector.dimensions")).isEqualTo("1536");
        assertThat(environment.getProperty("spring.ai.openai.embedding.options.dimensions")).isEqualTo("1536");
    }

    @Test
    @DisplayName("keeps explicit Ollama embedding runtime on the 1024 product dimension")
    void keepsExplicitOllamaRuntimeOnProductDimension() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("contexa.llm.selection.chat.priority", "ollama")
                .withProperty("contexa.llm.selection.embedding.priority", "ollama");

        postProcessor.postProcessEnvironment(environment, new SpringApplication());

        assertThat(environment.getProperty("contexa.vectorstore.pgvector.dimensions")).isEqualTo("1024");
        assertThat(environment.getProperty("spring.ai.vectorstore.pgvector.dimensions")).isEqualTo("1024");
        assertThat(environment.getProperty("spring.ai.openai.embedding.options.dimensions")).isEqualTo("1024");
        assertThat(environment.getProperty("spring.ai.model.chat")).isEqualTo("ollama");
        assertThat(environment.getProperty("spring.ai.model.embedding")).isEqualTo("ollama");
        assertThat(environment.getProperty("spring.ai.model.image")).isEqualTo("none");
        assertThat(environment.getProperty("spring.ai.model.moderation")).isEqualTo("none");
        assertThat(environment.getProperty("spring.ai.model.audio.speech")).isEqualTo("none");
        assertThat(environment.getProperty("spring.ai.model.audio.transcription")).isEqualTo("none");
    }

    @Test
    @DisplayName("loads the Contexa-owned overlay below host properties and above module defaults")
    void loadsOwnedOverlayWithoutOverridingHostProperties() {
        ByteArrayResource overlay = new ByteArrayResource("""
                server:
                  port: 9080
                contexa:
                  security:
                    zerotrust:
                      mode: ENFORCE
                spring:
                  ai:
                    vectorstore:
                      pgvector:
                        dimensions: 2048
                """.getBytes(StandardCharsets.UTF_8));
        MockEnvironment environment = new MockEnvironment()
                .withProperty("server.port", "9191");

        new ContexaDefaultPropertiesPostProcessor(overlay)
                .postProcessEnvironment(environment, new SpringApplication());

        assertThat(environment.getProperty("server.port")).isEqualTo("9191");
        assertThat(environment.getProperty("contexa.security.zerotrust.mode")).isEqualTo("ENFORCE");
        assertThat(environment.getProperty("spring.ai.vectorstore.pgvector.dimensions")).isEqualTo("2048");
    }

    @Test
    @DisplayName("keeps multi-provider chat dynamic while selecting the fixed embedding provider")
    void keepsMultiProviderChatDynamic() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("contexa.llm.selection.chat.priority", "ollama,openai")
                .withProperty("contexa.llm.selection.embedding.priority", "ollama");

        postProcessor.postProcessEnvironment(environment, new SpringApplication());

        assertThat(environment.getProperty("spring.ai.model.chat")).isNull();
        assertThat(environment.getProperty("spring.ai.model.embedding")).isEqualTo("ollama");
    }

    @Test
    @DisplayName("does not override explicit Spring AI model selectors")
    void doesNotOverrideExplicitSpringAiModelSelectors() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("contexa.llm.selection.chat.priority", "ollama")
                .withProperty("contexa.llm.selection.embedding.priority", "ollama")
                .withProperty("spring.ai.model.chat", "openai")
                .withProperty("spring.ai.model.embedding", "openai");

        postProcessor.postProcessEnvironment(environment, new SpringApplication());

        assertThat(environment.getProperty("spring.ai.model.chat")).isEqualTo("openai");
        assertThat(environment.getProperty("spring.ai.model.embedding")).isEqualTo("openai");
    }
}
