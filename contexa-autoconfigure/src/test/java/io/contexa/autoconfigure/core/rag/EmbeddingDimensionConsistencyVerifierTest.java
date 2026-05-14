package io.contexa.autoconfigure.core.rag;

import io.contexa.autoconfigure.properties.ContexaLlmSelectionProperties;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeBinding;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeCatalog;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeType;
import io.contexa.contexacore.std.rag.properties.PgVectorStoreProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class EmbeddingDimensionConsistencyVerifierTest {

    @Test
    @DisplayName("passes when selected Ollama embedding profile and pgvector dimensions are both 1024")
    void passesWhenOllamaAndPgVectorDimensionsMatch() {
        PgVectorStoreProperties vectorStoreProperties = new PgVectorStoreProperties();
        vectorStoreProperties.setDimensions(1024);
        ContexaLlmSelectionProperties selectionProperties = new ContexaLlmSelectionProperties();
        selectionProperties.getEmbedding().setPriority("ollama");
        LlmRuntimeCatalog runtimeCatalog = runtimeCatalog("ollama", "mxbai-embed-large");

        new EmbeddingDimensionConsistencyVerifier(
                vectorStoreProperties,
                selectionProperties,
                new MockEnvironment().withProperty("contexa.llm.selection.embedding.priority", "ollama"),
                runtimeCatalog,
                null).afterSingletonsInstantiated();
    }

    @Test
    @DisplayName("fails before vector storage when selected profile and pgvector dimensions differ")
    void failsWhenSelectedProfileAndPgVectorDimensionsDiffer() {
        PgVectorStoreProperties vectorStoreProperties = new PgVectorStoreProperties();
        vectorStoreProperties.setDimensions(1536);
        ContexaLlmSelectionProperties selectionProperties = new ContexaLlmSelectionProperties();
        selectionProperties.getEmbedding().setPriority("ollama");
        LlmRuntimeCatalog runtimeCatalog = runtimeCatalog("ollama", "mxbai-embed-large");

        assertThatThrownBy(() -> new EmbeddingDimensionConsistencyVerifier(
                vectorStoreProperties,
                selectionProperties,
                new MockEnvironment().withProperty("contexa.llm.selection.embedding.priority", "ollama"),
                runtimeCatalog,
                null).afterSingletonsInstantiated())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Embedding dimension mismatch")
                .hasMessageContaining("expectedDimension=1024")
                .hasMessageContaining("configuredPgVectorDimension=1536");
    }

    @Test
    @DisplayName("fails when embedding provider priority contains more than one provider")
    void failsWhenEmbeddingProviderPriorityContainsMoreThanOneProvider() {
        PgVectorStoreProperties vectorStoreProperties = new PgVectorStoreProperties();
        vectorStoreProperties.setDimensions(1024);
        ContexaLlmSelectionProperties selectionProperties = new ContexaLlmSelectionProperties();
        selectionProperties.getEmbedding().setPriority("ollama,openai");
        LlmRuntimeCatalog runtimeCatalog = runtimeCatalog("ollama", "mxbai-embed-large");

        assertThatThrownBy(() -> new EmbeddingDimensionConsistencyVerifier(
                vectorStoreProperties,
                selectionProperties,
                new MockEnvironment().withProperty("contexa.llm.selection.embedding.priority", "ollama,openai"),
                runtimeCatalog,
                null).afterSingletonsInstantiated())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Embedding runtime must use exactly one fixed provider");
    }

    @Test
    @DisplayName("fails fast for unknown embedding model without explicit dimension")
    void failsForUnknownModelWithoutExplicitDimension() {
        PgVectorStoreProperties vectorStoreProperties = new PgVectorStoreProperties();
        vectorStoreProperties.setDimensions(1024);
        ContexaLlmSelectionProperties selectionProperties = new ContexaLlmSelectionProperties();
        selectionProperties.getEmbedding().setPriority("ollama");
        LlmRuntimeCatalog runtimeCatalog = runtimeCatalog("ollama", "custom-embed");

        assertThatThrownBy(() -> new EmbeddingDimensionConsistencyVerifier(
                vectorStoreProperties,
                selectionProperties,
                new MockEnvironment()
                        .withProperty("contexa.llm.selection.embedding.priority", "ollama")
                        .withProperty("contexa.llm.embedding.ollama.model", "custom-embed"),
                runtimeCatalog,
                null).afterSingletonsInstantiated())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Unknown embedding model dimension")
                .hasMessageContaining("custom-embed");
    }

    @Test
    @DisplayName("uses configured runtime binding model id when provider model property is absent")
    void usesConfiguredRuntimeBindingModelIdWhenProviderModelPropertyIsAbsent() {
        PgVectorStoreProperties vectorStoreProperties = new PgVectorStoreProperties();
        vectorStoreProperties.setDimensions(1024);
        ContexaLlmSelectionProperties selectionProperties = new ContexaLlmSelectionProperties();
        selectionProperties.getEmbedding().setPriority("ollama");
        LlmRuntimeCatalog runtimeCatalog = runtimeCatalog("ollama", "custom-embed");

        assertThatThrownBy(() -> new EmbeddingDimensionConsistencyVerifier(
                vectorStoreProperties,
                selectionProperties,
                new MockEnvironment().withProperty("contexa.llm.selection.embedding.priority", "ollama"),
                runtimeCatalog,
                null).afterSingletonsInstantiated())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Unknown embedding model dimension")
                .hasMessageContaining("custom-embed");
    }

    @Test
    @DisplayName("passes for unknown embedding model when explicit dimension matches pgvector")
    void passesForUnknownModelWithExplicitDimension() {
        PgVectorStoreProperties vectorStoreProperties = new PgVectorStoreProperties();
        vectorStoreProperties.setDimensions(1536);
        ContexaLlmSelectionProperties selectionProperties = new ContexaLlmSelectionProperties();
        selectionProperties.getEmbedding().setPriority("ollama");
        LlmRuntimeCatalog runtimeCatalog = runtimeCatalog("ollama", "custom-embed");

        new EmbeddingDimensionConsistencyVerifier(
                vectorStoreProperties,
                selectionProperties,
                new MockEnvironment()
                        .withProperty("contexa.llm.selection.embedding.priority", "ollama")
                        .withProperty("contexa.llm.embedding.ollama.model", "custom-embed")
                        .withProperty("contexa.llm.embedding.ollama.dimensions", "1536"),
                runtimeCatalog,
                null).afterSingletonsInstantiated();
    }

    private LlmRuntimeCatalog runtimeCatalog(String provider, String modelId) {
        LlmRuntimeCatalog runtimeCatalog = mock(LlmRuntimeCatalog.class);
        when(runtimeCatalog.getEmbeddingBindings()).thenReturn(List.of(new LlmRuntimeBinding(
                provider + "Embedding",
                provider + "EmbeddingModel",
                provider,
                modelId,
                Set.of(modelId),
                LlmRuntimeType.EMBEDDING,
                false,
                "test")));
        return runtimeCatalog;
    }
}
