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
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThat;

class EmbeddingDimensionResolverTest {

    @Test
    @DisplayName("resolves OpenAI text-embedding-3-small to the 1024 product default")
    void resolvesOpenAiSmallToProductDefault() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("contexa.llm.selection.embedding.priority", "openai");

        EmbeddingDimensionResolver.ResolvedDimension resolved =
                EmbeddingDimensionResolver.resolveForEnvironment(environment);

        assertThat(resolved.provider()).isEqualTo("openai");
        assertThat(resolved.modelId()).isEqualTo("text-embedding-3-small");
        assertThat(resolved.dimensions()).isEqualTo(1024);
        assertThat(resolved.modelKnown()).isTrue();
        assertThat(resolved.explicit()).isFalse();
    }

    @Test
    @DisplayName("resolves Ollama mxbai-embed-large to 1024")
    void resolvesOllamaMxbaiTo1024() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("contexa.llm.selection.embedding.priority", "ollama");

        EmbeddingDimensionResolver.ResolvedDimension resolved =
                EmbeddingDimensionResolver.resolveForEnvironment(environment);

        assertThat(resolved.provider()).isEqualTo("ollama");
        assertThat(resolved.modelId()).isEqualTo("mxbai-embed-large");
        assertThat(resolved.dimensions()).isEqualTo(1024);
        assertThat(resolved.modelKnown()).isTrue();
    }

    @Test
    @DisplayName("honors explicit 1536 vector-store override")
    void honorsExplicitVectorStoreOverride() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("contexa.vectorstore.pgvector.dimensions", "1536");

        EmbeddingDimensionResolver.ResolvedDimension resolved =
                EmbeddingDimensionResolver.resolveForEnvironment(environment);

        assertThat(resolved.dimensions()).isEqualTo(1536);
        assertThat(resolved.explicit()).isTrue();
        assertThat(resolved.source()).isEqualTo("vector-store-property");
    }

    @Test
    @DisplayName("marks unknown model as not known unless an explicit dimension is configured")
    void marksUnknownModelAsUnknown() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("contexa.llm.selection.embedding.priority", "ollama")
                .withProperty("contexa.llm.embedding.ollama.model", "custom-embed");

        EmbeddingDimensionResolver.ResolvedDimension resolved =
                EmbeddingDimensionResolver.resolveForEnvironment(environment);

        assertThat(resolved.modelKnown()).isFalse();
        assertThat(resolved.explicit()).isFalse();
        assertThat(resolved.dimensions()).isEqualTo(1024);
    }

    @Test
    @DisplayName("accepts explicit dimension for unknown model")
    void acceptsExplicitDimensionForUnknownModel() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("contexa.llm.selection.embedding.priority", "ollama")
                .withProperty("contexa.llm.embedding.ollama.model", "custom-embed")
                .withProperty("contexa.llm.embedding.ollama.dimensions", "1536");

        EmbeddingDimensionResolver.ResolvedDimension resolved =
                EmbeddingDimensionResolver.resolveForEnvironment(environment);

        assertThat(resolved.modelKnown()).isTrue();
        assertThat(resolved.explicit()).isTrue();
        assertThat(resolved.dimensions()).isEqualTo(1536);
    }
}
