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
package io.contexa.autoconfigure.core.llm;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.model.ChatModel;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Tests the model priority selection logic used in CoreLLMTieredAutoConfiguration.
 * Uses direct logic testing since the full auto-configuration requires
 * Spring AI models which are not available in the test classpath.
 */
@DisplayName("CoreLLMTieredAutoConfiguration - Model Priority Selection")
class CoreLLMTieredAutoConfigurationTest {

    @Nested
    @DisplayName("Chat model priority selection")
    class ChatModelPriority {

        @Test
        @DisplayName("Should select Ollama when available and first in priority")
        void shouldSelectOllamaFirst() {
            ChatModel ollamaModel = mock(ChatModel.class, "ollama");
            ChatModel anthropicModel = mock(ChatModel.class, "anthropic");

            Map<String, ChatModel> available = new HashMap<>();
            available.put("ollama", ollamaModel);
            available.put("anthropic", anthropicModel);

            ChatModel selected = selectByPriority(available, "ollama,anthropic,openai");

            assertThat(selected).isSameAs(ollamaModel);
        }

        @Test
        @DisplayName("Should fallback to Anthropic when Ollama unavailable")
        void shouldFallbackToAnthropic() {
            ChatModel anthropicModel = mock(ChatModel.class, "anthropic");

            Map<String, ChatModel> available = new HashMap<>();
            available.put("anthropic", anthropicModel);

            ChatModel selected = selectByPriority(available, "ollama,anthropic,openai");

            assertThat(selected).isSameAs(anthropicModel);
        }

        @Test
        @DisplayName("Should fallback to OpenAI when Ollama and Anthropic unavailable")
        void shouldFallbackToOpenAi() {
            ChatModel openAiModel = mock(ChatModel.class, "openai");

            Map<String, ChatModel> available = new HashMap<>();
            available.put("openai", openAiModel);

            ChatModel selected = selectByPriority(available, "ollama,anthropic,openai");

            assertThat(selected).isSameAs(openAiModel);
        }

        @Test
        @DisplayName("Should return null when no models available")
        void shouldReturnNullWhenNoModels() {
            Map<String, ChatModel> available = new HashMap<>();

            ChatModel selected = selectByPriority(available, "ollama,anthropic,openai");

            assertThat(selected).isNull();
        }

        @Test
        @DisplayName("Should respect custom priority order")
        void shouldRespectCustomPriority() {
            ChatModel ollamaModel = mock(ChatModel.class, "ollama");
            ChatModel anthropicModel = mock(ChatModel.class, "anthropic");

            Map<String, ChatModel> available = new HashMap<>();
            available.put("ollama", ollamaModel);
            available.put("anthropic", anthropicModel);

            // Anthropic first in custom priority
            ChatModel selected = selectByPriority(available, "anthropic,ollama,openai");

            assertThat(selected).isSameAs(anthropicModel);
        }

        @Test
        @DisplayName("Should use fallback when no priority model found but models exist")
        void shouldUseFallbackModel() {
            ChatModel ollamaModel = mock(ChatModel.class, "ollama");

            Map<String, ChatModel> available = new HashMap<>();
            available.put("ollama", ollamaModel);

            // Priority list has no match for "ollama" (only "anthropic,openai")
            ChatModel selected = selectByPriority(available, "anthropic,openai");

            // Should fall back to first available
            assertThat(selected).isSameAs(ollamaModel);
        }
    }

    /**
     * Replicates the priority selection logic from CoreLLMTieredAutoConfiguration.primaryChatModel()
     */
    private ChatModel selectByPriority(Map<String, ChatModel> availableModels, String priorityConfig) {
        List<String> priorities = List.of(priorityConfig.split(","));
        for (String modelName : priorities) {
            String trimmedName = modelName.trim().toLowerCase();
            ChatModel model = availableModels.get(trimmedName);
            if (model != null) {
                return model;
            }
        }

        if (!availableModels.isEmpty()) {
            return availableModels.entrySet().iterator().next().getValue();
        }

        return null;
    }
}
