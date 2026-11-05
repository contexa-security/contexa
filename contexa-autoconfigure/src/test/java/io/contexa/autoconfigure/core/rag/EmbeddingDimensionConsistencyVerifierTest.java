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
package io.contexa.autoconfigure.core.rag;

import io.contexa.autoconfigure.properties.ContexaLlmSelectionProperties;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeBinding;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeCatalog;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeType;
import io.contexa.contexacore.std.rag.properties.PgVectorStoreProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
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

    /** Earlier versions asked OpenAI for 1024 on the application's behalf: Spring AI's own default no longer fits such a table. */
    @Test
    @DisplayName("tells an earlier OpenAI store how to keep its vectors")
    void tellsAnEarlierOpenAiStoreHowToKeepItsVectors() throws SQLException {
        PgVectorStoreProperties vectorStoreProperties = new PgVectorStoreProperties();
        vectorStoreProperties.setDimensions(1536);

        assertThatThrownBy(() -> new EmbeddingDimensionConsistencyVerifier(
                vectorStoreProperties,
                new ContexaLlmSelectionProperties(),
                new MockEnvironment(),
                runtimeCatalog("openai", "openAiEmbeddingModel"),
                existingTable(1024)).afterSingletonsInstantiated())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("existingTableDimension=1024")
                .hasMessageContaining("spring.ai.openai.embedding.options.model=text-embedding-3-small")
                .hasMessageContaining("spring.ai.openai.embedding.options.dimensions=1024");
    }

    @Test
    @DisplayName("does not offer OpenAI's settings to another provider's table")
    void doesNotOfferOpenAiSettingsToAnotherProvidersTable() throws SQLException {
        PgVectorStoreProperties vectorStoreProperties = new PgVectorStoreProperties();
        vectorStoreProperties.setDimensions(1024);

        assertThatThrownBy(() -> new EmbeddingDimensionConsistencyVerifier(
                vectorStoreProperties,
                new ContexaLlmSelectionProperties(),
                new MockEnvironment(),
                runtimeCatalog("ollama", "mxbai-embed-large"),
                existingTable(768)).afterSingletonsInstantiated())
                .hasMessageContaining("existingTableDimension=768")
                .hasMessageNotContaining("spring.ai.openai");
    }

    /** The store was told a size, so the check against the store passes: only the model's own output shows that nothing could be stored. */
    @Test
    @DisplayName("refuses a store size the OpenAI model does not produce")
    void refusesAStoreSizeTheOpenAiModelDoesNotProduce() {
        PgVectorStoreProperties vectorStoreProperties = new PgVectorStoreProperties();
        vectorStoreProperties.setDimensions(1024);

        assertThatThrownBy(() -> new EmbeddingDimensionConsistencyVerifier(
                vectorStoreProperties,
                new ContexaLlmSelectionProperties(),
                new MockEnvironment().withProperty("contexa.vectorstore.pgvector.dimensions", "1024"),
                runtimeCatalog("openai", "openAiEmbeddingModel"),
                null).afterSingletonsInstantiated())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("modelOutputDimension=1536")
                .hasMessageContaining("configuredPgVectorDimension=1024");
    }

    @Test
    @DisplayName("refuses a store size Ollama's model cannot produce")
    void refusesAStoreSizeOllamasModelCannotProduce() {
        PgVectorStoreProperties vectorStoreProperties = new PgVectorStoreProperties();
        vectorStoreProperties.setDimensions(1536);

        assertThatThrownBy(() -> new EmbeddingDimensionConsistencyVerifier(
                vectorStoreProperties,
                new ContexaLlmSelectionProperties(),
                new MockEnvironment().withProperty("contexa.vectorstore.pgvector.dimensions", "1536"),
                runtimeCatalog("ollama", "mxbai-embed-large"),
                null).afterSingletonsInstantiated())
                .hasMessageContaining("modelOutputDimension=1024");
    }

    @Test
    @DisplayName("passes a store sized to the length the application asked of its model")
    void passesAStoreSizedToTheLengthTheApplicationAskedOfItsModel() {
        PgVectorStoreProperties vectorStoreProperties = new PgVectorStoreProperties();
        vectorStoreProperties.setDimensions(1024);

        new EmbeddingDimensionConsistencyVerifier(
                vectorStoreProperties,
                new ContexaLlmSelectionProperties(),
                new MockEnvironment()
                        .withProperty("spring.ai.openai.embedding.options.model", "text-embedding-3-small")
                        .withProperty("spring.ai.openai.embedding.options.dimensions", "1024"),
                runtimeCatalog("openai", "openAiEmbeddingModel"),
                null).afterSingletonsInstantiated();
    }

    private DataSource existingTable(int dimensions) throws SQLException {
        Connection connection = mock(Connection.class, RETURNS_DEEP_STUBS);
        PreparedStatement statement = mock(PreparedStatement.class);
        ResultSet resultSet = mock(ResultSet.class);
        when(connection.getMetaData().getDatabaseProductName()).thenReturn("PostgreSQL");
        when(connection.prepareStatement(anyString())).thenReturn(statement);
        when(statement.executeQuery()).thenReturn(resultSet);
        when(resultSet.next()).thenReturn(true);
        when(resultSet.getString(1)).thenReturn("vector(" + dimensions + ")");
        DataSource dataSource = mock(DataSource.class);
        when(dataSource.getConnection()).thenReturn(connection);
        return dataSource;
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
