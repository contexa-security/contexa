package io.contexa.autoconfigure.llm;

import io.contexa.autoconfigure.core.llm.CoreLLMTieredAutoConfiguration;
import io.contexa.autoconfigure.properties.ContexaProperties;
import org.junit.jupiter.api.Test;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.ollama.OllamaEmbeddingModel;
import org.springframework.ai.openai.OpenAiEmbeddingModel;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.ResponseErrorHandler;

import java.util.Collections;
import java.util.Iterator;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class CoreLLMTieredAutoConfigurationEmbeddingTest {

    private CoreLLMTieredAutoConfiguration createConfiguration(String embeddingPriority) {
        CoreLLMTieredAutoConfiguration configuration = new CoreLLMTieredAutoConfiguration();
        ContexaProperties properties = new ContexaProperties();
        properties.getLlm().setEmbeddingModelPriority(embeddingPriority);
        ReflectionTestUtils.setField(configuration, "contexaProperties", properties);
        return configuration;
    }

    @Test
    void shouldSelectOllamaEmbeddingModelByDefaultPriority() {
        CoreLLMTieredAutoConfiguration configuration = createConfiguration("ollama,openai");

        OllamaEmbeddingModel ollamaEmbeddingModel = mock(OllamaEmbeddingModel.class);
        OpenAiEmbeddingModel openAiEmbeddingModel = mock(OpenAiEmbeddingModel.class);

        EmbeddingModel selected = configuration.primaryEmbeddingModel(
                providerOf(null),
                providerOf(ollamaEmbeddingModel),
                providerOf(openAiEmbeddingModel));

        assertThat(selected).isSameAs(ollamaEmbeddingModel);
    }

    @Test
    void shouldSelectOpenAiEmbeddingModelWhenPriorityChanges() {
        CoreLLMTieredAutoConfiguration configuration = createConfiguration("openai,ollama");

        OllamaEmbeddingModel ollamaEmbeddingModel = mock(OllamaEmbeddingModel.class);
        OpenAiEmbeddingModel openAiEmbeddingModel = mock(OpenAiEmbeddingModel.class);

        EmbeddingModel selected = configuration.primaryEmbeddingModel(
                providerOf(null),
                providerOf(ollamaEmbeddingModel),
                providerOf(openAiEmbeddingModel));

        assertThat(selected).isSameAs(openAiEmbeddingModel);
    }

    @Test
    void shouldPreferDedicatedOllamaEmbeddingRuntimeWhenAvailable() {
        CoreLLMTieredAutoConfiguration configuration = createConfiguration("ollama,openai");

        OllamaEmbeddingModel dedicatedEmbeddingModel = mock(OllamaEmbeddingModel.class);
        OllamaEmbeddingModel standardEmbeddingModel = mock(OllamaEmbeddingModel.class);
        OpenAiEmbeddingModel openAiEmbeddingModel = mock(OpenAiEmbeddingModel.class);

        EmbeddingModel selected = configuration.primaryEmbeddingModel(
                providerOf(dedicatedEmbeddingModel),
                providerOf(standardEmbeddingModel),
                providerOf(openAiEmbeddingModel));

        assertThat(selected).isSameAs(dedicatedEmbeddingModel);
    }

    @Test
    void shouldFailFastWhenDedicatedEmbeddingRuntimeMissingBaseUrl() {
        CoreLLMTieredAutoConfiguration configuration = createConfiguration("ollama,openai");
        ContexaProperties properties = (ContexaProperties) ReflectionTestUtils.getField(configuration, "contexaProperties");
        properties.getLlm().getEmbedding().getOllama().setDedicatedRuntimeEnabled(true);

        assertThatThrownBy(() -> configuration.contexaDedicatedEmbeddingOllamaApi(
                providerOf(null),
                providerOf(null),
                mock(ResponseErrorHandler.class)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("contexa.llm.embedding.ollama.base-url");
    }

    private static <T> ObjectProvider<T> providerOf(T value) {
        return new ObjectProvider<>() {
            @Override
            public T getObject() {
                if (value == null) {
                    throw new IllegalStateException("No bean available");
                }
                return value;
            }

            @Override
            public T getObject(Object... args) {
                return getObject();
            }

            @Override
            public T getIfAvailable() {
                return value;
            }

            @Override
            public T getIfAvailable(Supplier<T> defaultSupplier) {
                return value != null ? value : defaultSupplier.get();
            }

            @Override
            public T getIfUnique() {
                return value;
            }

            @Override
            public T getIfUnique(Supplier<T> defaultSupplier) {
                return value != null ? value : defaultSupplier.get();
            }

            @Override
            public Iterator<T> iterator() {
                return value == null ? Collections.emptyIterator() : Collections.singleton(value).iterator();
            }

            @Override
            public Stream<T> stream() {
                return value == null ? Stream.empty() : Stream.of(value);
            }

            @Override
            public Stream<T> orderedStream() {
                return stream();
            }
        };
    }
}