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

import io.contexa.contexacore.properties.ContexaRagProperties;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelection;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelectionSource;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.PromptAssembler;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocumentReader;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionInUse;
import io.contexa.contexacore.std.llm.gate.ModelServerGates;
import io.contexa.contexacore.std.rag.QueryTransformPrompt;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.preretrieval.query.transformation.QueryTransformer;
import org.springframework.beans.factory.ObjectProvider;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Plan 6-7: the three query rewrites of the RAG searches draw from their product documents the very prompts the code
 * drew before the move, letter for letter, and draw the version an organization made once the resolver chooses it.
 */
class QueryTransformPromptVersionTest {

    private static final String QUERY = "who exported the payroll report last night";
    private final CoreRAGAutoConfiguration configuration = new CoreRAGAutoConfiguration(new ContexaRagProperties());

    @Test
    void everyQueryRewriteDrawsTheGoldenPromptFromItsProductDocument() throws IOException {
        for (QueryTransformPrompt prompt : QueryTransformPrompt.ALL) {
            assertThat(drawn(prompt, PromptVersionInUse.productOnly())).as(prompt.prompt()).isEqualTo(golden(prompt));
        }
    }

    @Test
    void everyQueryRewriteDrawsTheChosenVersion() {
        for (QueryTransformPrompt prompt : QueryTransformPrompt.ALL) {
            AssembledPrompt two = new PromptAssembler().apply(prompt.product(), new PromptVersionDocumentReader().read(
                    "prompt: " + prompt.prompt() + "\nbasedOn: v1.0\ntitle: Ours\nuser:\n"
                            + "  - key: purpose\n    text: |\n      Rewrite the query for the finance department's records:\n"
                            + "  - key: guidelines\n    delete: true\n"));
            PromptVersionInUse versions = new PromptVersionInUse(
                    () -> (context, subject) -> new PromptBundleSelection("v2.0", PromptBundleSelectionSource.REGISTRY),
                    () -> (asked, version) -> prompt.prompt().equals(asked) && "v2.0".equals(version) ? Optional.of(two)
                            : Optional.empty());

            String drawn = drawn(prompt, versions);

            assertThat(drawn).as(prompt.prompt()).contains("Rewrite the query for the finance department's records:",
                    "Some parts of this text were written by your organization.", "Original Query: " + QUERY,
                    "Return only the optimized query.").doesNotContain("Optimization Guidelines:");
        }
    }

    /** The user prompt the transformer of the prompt sends to the model, through the real bean. */
    @SuppressWarnings("unchecked")
    private String drawn(QueryTransformPrompt prompt, PromptVersionInUse versions) {
        ChatClient.Builder builder = mock(ChatClient.Builder.class);
        ChatClient client = mock(ChatClient.class, RETURNS_DEEP_STUBS);
        when(builder.build()).thenReturn(client);
        when(client.prompt().user(anyString()).call().content()).thenReturn("rewritten");
        ObjectProvider<ModelServerGates> gates = mock(ObjectProvider.class);
        ObjectProvider<ChatModel> model = mock(ObjectProvider.class);
        ObjectProvider<PromptVersionInUse> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable(any(Supplier.class))).thenReturn(versions);
        QueryTransformer transformer = prompt == QueryTransformPrompt.BEHAVIOR
                ? configuration.behaviorQueryTransformer(builder, gates, model, provider)
                : prompt == QueryTransformPrompt.RISK
                ? configuration.riskQueryTransformer(builder, gates, model, provider)
                : configuration.policyQueryTransformer(builder, gates, model, provider);

        assertThat(transformer.transform(new Query(QUERY)).text()).isEqualTo("rewritten");
        ArgumentCaptor<String> sent = ArgumentCaptor.forClass(String.class);
        verify(client.prompt(), atLeastOnce()).user(sent.capture());
        return sent.getAllValues().stream().filter(text -> text.contains(QUERY)).findFirst().orElseThrow();
    }

    private static String golden(QueryTransformPrompt prompt) throws IOException {
        try (InputStream input = QueryTransformPromptVersionTest.class.getClassLoader()
                .getResourceAsStream("prompt-versions-golden/" + prompt.prompt() + "/user-query.txt")) {
            assertThat(input).as(prompt.prompt()).isNotNull();
            // A checkout may turn the golden files' line breaks into CRLF; the prompts break lines with LF.
            return new String(input.readAllBytes(), StandardCharsets.UTF_8).replace("\r\n", "\n");
        }
    }
}
