package io.contexa.autoconfigure.compat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThat;

class ContexaDefaultPropertiesPostProcessorTest {

    private final ContexaDefaultPropertiesPostProcessor postProcessor = new ContexaDefaultPropertiesPostProcessor();

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
                .withProperty("contexa.llm.selection.embedding.priority", "ollama");

        postProcessor.postProcessEnvironment(environment, new SpringApplication());

        assertThat(environment.getProperty("contexa.vectorstore.pgvector.dimensions")).isEqualTo("1024");
        assertThat(environment.getProperty("spring.ai.vectorstore.pgvector.dimensions")).isEqualTo("1024");
        assertThat(environment.getProperty("spring.ai.openai.embedding.options.dimensions")).isEqualTo("1024");
    }
}
