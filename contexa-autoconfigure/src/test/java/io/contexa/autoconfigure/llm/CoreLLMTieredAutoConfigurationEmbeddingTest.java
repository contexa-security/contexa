package io.contexa.autoconfigure.llm;

import io.contexa.autoconfigure.core.llm.CoreLLMTieredAutoConfiguration;
import io.contexa.autoconfigure.properties.ContexaLlmSelectionProperties;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeCatalog;
import org.junit.jupiter.api.Test;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CoreLLMTieredAutoConfigurationEmbeddingTest {

    private CoreLLMTieredAutoConfiguration createConfiguration(String embeddingPriority) {
        CoreLLMTieredAutoConfiguration configuration = new CoreLLMTieredAutoConfiguration();
        ContexaProperties properties = new ContexaProperties();
        properties.getLlm().setEmbeddingModelPriority(embeddingPriority);
        ReflectionTestUtils.setField(configuration, "contexaProperties", properties);
        ReflectionTestUtils.setField(configuration, "contexaLlmSelectionProperties", new ContexaLlmSelectionProperties());
        return configuration;
    }

    @Test
    void shouldResolveFixedPrimaryEmbeddingModelThroughRuntimeCatalog() {
        CoreLLMTieredAutoConfiguration configuration = createConfiguration("ollama,openai");
        LlmRuntimeCatalog catalog = mock(LlmRuntimeCatalog.class);
        EmbeddingModel embeddingModel = mock(EmbeddingModel.class);
        when(catalog.resolvePrimaryEmbeddingModel("openai")).thenReturn(Optional.of(embeddingModel));

        EmbeddingModel selected = configuration.fixedPrimaryEmbeddingModel(catalog);

        assertThat(selected).isSameAs(embeddingModel);
        verify(catalog).resolvePrimaryEmbeddingModel("openai");
    }

    @Test
    void shouldPreferSelectionPriorityOverLegacyEmbeddingModelPriority() {
        CoreLLMTieredAutoConfiguration configuration = createConfiguration("legacy-openai,legacy-ollama");
        ContexaLlmSelectionProperties selectionProperties = new ContexaLlmSelectionProperties();
        selectionProperties.getEmbedding().setPriority("voyageai");
        ReflectionTestUtils.setField(configuration, "contexaLlmSelectionProperties", selectionProperties);
        LlmRuntimeCatalog catalog = mock(LlmRuntimeCatalog.class);
        EmbeddingModel embeddingModel = mock(EmbeddingModel.class);
        when(catalog.resolvePrimaryEmbeddingModel("voyageai")).thenReturn(Optional.of(embeddingModel));

        EmbeddingModel selected = configuration.fixedPrimaryEmbeddingModel(catalog);

        assertThat(selected).isSameAs(embeddingModel);
        verify(catalog).resolvePrimaryEmbeddingModel("voyageai");
    }

    @Test
    void shouldFailFastWhenNoFixedEmbeddingModelCanBeResolved() {
        CoreLLMTieredAutoConfiguration configuration = createConfiguration("openai,ollama");
        LlmRuntimeCatalog catalog = mock(LlmRuntimeCatalog.class);
        when(catalog.resolvePrimaryEmbeddingModel("openai")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> configuration.fixedPrimaryEmbeddingModel(catalog))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No embedding runtime binding could be resolved for fixed provider");
    }

    @Test
    void shouldRejectMultipleFixedEmbeddingProviders() {
        CoreLLMTieredAutoConfiguration configuration = createConfiguration("legacy-openai");
        ContexaLlmSelectionProperties selectionProperties = new ContexaLlmSelectionProperties();
        selectionProperties.getEmbedding().setPriority("openai,ollama");
        ReflectionTestUtils.setField(configuration, "contexaLlmSelectionProperties", selectionProperties);

        assertThatThrownBy(() -> configuration.fixedPrimaryEmbeddingModel(mock(LlmRuntimeCatalog.class)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Embedding runtime must be fixed to exactly one provider");
    }

    @Test
    void shouldRejectDynamicPriorityEmbeddingSelection() {
        CoreLLMTieredAutoConfiguration configuration = createConfiguration("openai");

        assertThatThrownBy(() -> configuration.dynamicPriorityPrimaryEmbeddingModel(mock(LlmRuntimeCatalog.class)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Dynamic priority embedding selection is not supported");
    }

    @Test
    void shouldSupportSpringPrimaryModeForEmbeddingSelection() {
        CoreLLMTieredAutoConfiguration configuration = createConfiguration("ollama,openai");
        ContexaLlmSelectionProperties selectionProperties = new ContexaLlmSelectionProperties();
        selectionProperties.getEmbedding().setMode(ContexaLlmSelectionProperties.Mode.SPRING_PRIMARY);
        ReflectionTestUtils.setField(configuration, "contexaLlmSelectionProperties", selectionProperties);
        LlmRuntimeCatalog catalog = mock(LlmRuntimeCatalog.class);
        EmbeddingModel embeddingModel = mock(EmbeddingModel.class);
        when(catalog.resolveSpringPrimaryEmbeddingModel()).thenReturn(Optional.of(embeddingModel));

        EmbeddingModel selected = configuration.springPrimaryEmbeddingModel(catalog);

        assertThat(selected).isSameAs(embeddingModel);
        verify(catalog).resolveSpringPrimaryEmbeddingModel();
    }

    @Test
    void shouldFailFastWhenDedicatedEmbeddingRuntimeMissingBaseUrl() {
        CoreLLMTieredAutoConfiguration configuration = createConfiguration("ollama,openai");
        ContexaProperties properties = (ContexaProperties) ReflectionTestUtils.getField(configuration, "contexaProperties");
        properties.getLlm().getEmbedding().getOllama().setDedicatedRuntimeEnabled(true);

        ObjectProvider<RestClient.Builder> restClientBuilderProvider = mock(ObjectProvider.class);
        ObjectProvider<WebClient.Builder> webClientBuilderProvider = mock(ObjectProvider.class);
        ObjectProvider<ResponseErrorHandler> responseErrorHandlerProvider = mock(ObjectProvider.class);

        assertThatThrownBy(() -> configuration.contexaDedicatedEmbeddingOllamaApi(
                restClientBuilderProvider,
                webClientBuilderProvider,
                responseErrorHandlerProvider))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("contexa.llm.embedding.ollama.base-url");
    }
}
