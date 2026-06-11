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
package io.contexa.contexacore.std.llm.strategy;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.llm.client.ExecutionContext;
import io.contexa.contexacore.std.llm.model.DynamicModelRegistry;
import io.contexa.contexacore.std.llm.model.ModelDescriptor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ai.chat.model.ChatModel;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DynamicModelSelectionStrategyTest {

    @Mock
    private DynamicModelRegistry modelRegistry;

    @Mock
    private ChatModel primaryChatModel;

    @Mock
    private ChatModel explicitModel;

    @Mock
    private ChatModel tierModel;

    @Test
    void selectModelShouldPreferExplicitRequestedModelBeforeTier() {
        TieredLLMProperties properties = new TieredLLMProperties();
        properties.getLayer1().setModel("tier-model");
        DynamicModelSelectionStrategy strategy = new DynamicModelSelectionStrategy(modelRegistry, properties, primaryChatModel);

        when(modelRegistry.getModel("client-model")).thenReturn(explicitModel);
        when(modelRegistry.getDescriptor("client-model")).thenReturn(ModelDescriptor.builder()
                .modelId("client-model")
                .provider("ollama")
                .build());

        ExecutionContext context = ExecutionContext.builder()
                .preferredModel("client-model")
                .tier(1)
                .build();

        ChatModel selected = strategy.selectModel(context);

        assertThat(selected).isSameAs(explicitModel);
        assertThat(context.getMetadata())
                .containsEntry("requestedModelId", "client-model")
                .containsEntry("requestedModelSourceKey", "executionContext.preferredModel")
                .containsEntry("selectedModelId", "client-model")
                .containsEntry("runtimeModelId", "client-model")
                .containsEntry("selectedModelProvider", "ollama")
                .containsEntry("modelSelectionSource", "explicit_model")
                .containsEntry("modelSelectionFallbackUsed", false);
        verify(modelRegistry).getModel("client-model");
        verify(modelRegistry, never()).getModel("tier-model");
    }

    @Test
    void selectModelShouldFallbackToTierWhenExplicitRequestedModelIsUnavailable() {
        TieredLLMProperties properties = new TieredLLMProperties();
        properties.getLayer1().setModel("tier-model");
        DynamicModelSelectionStrategy strategy = new DynamicModelSelectionStrategy(modelRegistry, properties, primaryChatModel);

        when(modelRegistry.getModel("missing-model")).thenThrow(new IllegalStateException("missing"));
        when(modelRegistry.getModel("tier-model")).thenReturn(tierModel);
        when(modelRegistry.getDescriptor("tier-model")).thenReturn(ModelDescriptor.builder()
                .modelId("tier-model")
                .provider("openai")
                .build());

        ExecutionContext context = ExecutionContext.builder()
                .preferredModel("missing-model")
                .tier(1)
                .build();

        ChatModel selected = strategy.selectModel(context);

        assertThat(selected).isSameAs(tierModel);
        assertThat(context.getMetadata())
                .containsEntry("requestedModelId", "missing-model")
                .containsEntry("selectedModelId", "tier-model")
                .containsEntry("runtimeModelId", "tier-model")
                .containsEntry("selectedModelProvider", "openai")
                .containsEntry("modelSelectionSource", "tier:1")
                .containsEntry("modelSelectionFallbackUsed", true)
                .containsEntry("modelSelectionFailure", "Requested model not available: missing-model");
    }
}
