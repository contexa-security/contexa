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
