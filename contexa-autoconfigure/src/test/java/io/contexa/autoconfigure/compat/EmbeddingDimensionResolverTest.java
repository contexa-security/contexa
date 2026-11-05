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
    @DisplayName("follows Spring AI's own default when the application names no OpenAI model")
    void followsSpringAiWhenTheApplicationNamesNoOpenAiModel() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("contexa.llm.selection.embedding.priority", "openai");

        EmbeddingDimensionResolver.ResolvedDimension resolved =
                EmbeddingDimensionResolver.resolveForEnvironment(environment);

        assertThat(resolved.provider()).isEqualTo("openai");
        assertThat(resolved.modelId()).isEqualTo("text-embedding-ada-002");
        assertThat(resolved.dimensions()).isEqualTo(1536);
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

    /** Contexa asks nothing of the application's model, so what counts is what each model produces by itself. */
    @Test
    @DisplayName("reads what the named OpenAI model produces by itself")
    void readsWhatTheNamedOpenAiModelProducesByItself() {
        assertThat(resolveOpenAi("text-embedding-ada-002").dimensions()).isEqualTo(1536);
        assertThat(resolveOpenAi("text-embedding-3-small").dimensions()).isEqualTo(1536);
        assertThat(resolveOpenAi("text-embedding-3-large").dimensions()).isEqualTo(3072);
        assertThat(resolveOpenAi("a-model-nobody-knows").modelKnown()).isFalse();
    }

    @Test
    @DisplayName("keeps the length the application asked of its OpenAI model")
    void keepsTheLengthTheApplicationAskedFor() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("contexa.llm.selection.embedding.priority", "openai")
                .withProperty("spring.ai.openai.embedding.options.model", "text-embedding-3-small")
                .withProperty("spring.ai.openai.embedding.options.dimensions", "1024");

        assertThat(EmbeddingDimensionResolver.resolveForEnvironment(environment).dimensions()).isEqualTo(1024);
    }

    @Test
    @DisplayName("reads an unnamed provider from what the application selected in Spring AI")
    void readsAnUnnamedProviderFromSpringAisSelection() {
        MockEnvironment environment = new MockEnvironment().withProperty("spring.ai.model.embedding", "ollama");

        EmbeddingDimensionResolver.ResolvedDimension resolved = EmbeddingDimensionResolver.resolveForEnvironment(environment);

        assertThat(resolved.provider()).isEqualTo("ollama");
        assertThat(resolved.dimensions()).isEqualTo(1024);
    }

    /** Ollama's vectors are 1024 long and cannot be asked for more: 1536 here would stop an application that only has Ollama. */
    @Test
    @DisplayName("does not assume OpenAI of an application that does not have it")
    void doesNotAssumeOpenAiOfAnApplicationThatDoesNotHaveIt() {
        assertThat(EmbeddingDimensionResolver.providerOnClassPath(new ClassLoader(null) {
        })).isEqualTo("ollama");
        assertThat(EmbeddingDimensionResolver.providerOnClassPath(getClass().getClassLoader())).isEqualTo("openai");
    }

    @Test
    @DisplayName("tells what the model produces from what the store was told")
    void tellsWhatTheModelProducesFromWhatTheStoreWasTold() {
        MockEnvironment environment = new MockEnvironment().withProperty("contexa.vectorstore.pgvector.dimensions", "1024");

        assertThat(EmbeddingDimensionResolver.modelOutputDimensions(environment, "openai", "text-embedding-ada-002")).hasValue(1536);
        assertThat(EmbeddingDimensionResolver.modelOutputDimensions(environment, "ollama", "custom-embed")).isEmpty();
    }

    private static EmbeddingDimensionResolver.ResolvedDimension resolveOpenAi(String model) {
        return EmbeddingDimensionResolver.resolveForEnvironment(new MockEnvironment()
                .withProperty("contexa.llm.selection.embedding.priority", "openai")
                .withProperty("spring.ai.openai.embedding.options.model", model));
    }
}
