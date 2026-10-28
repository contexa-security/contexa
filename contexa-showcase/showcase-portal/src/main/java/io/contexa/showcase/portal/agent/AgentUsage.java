package io.contexa.showcase.portal.agent;

import org.springframework.ai.anthropic.api.AnthropicApi;
import org.springframework.ai.chat.metadata.Usage;
import org.springframework.ai.openai.api.OpenAiApi;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The business agent's token counts, counted the same way for both providers (docs/agent Agent중심-화면 AC-8): the prompt
 * tokens are every input token of the call as OpenAI counts them, and the cached prompt tokens are the part of them the
 * provider served from its prompt cache. Spring AI's prompt tokens are Anthropic's input tokens alone, since Anthropic
 * counts its cache reads and writes apart. The portal holds no Contexa dependency, so this mirrors what the engine's
 * own usage reading (Contexa's ProviderUsage) does for control D.
 */
final class AgentUsage {

    private AgentUsage() {
    }

    /** Every input token of the call; null when the provider reported none. */
    static Integer promptTokens(Usage usage) {
        if (usage == null || usage.getPromptTokens() == null) {
            return null;
        }
        if (usage.getNativeUsage() instanceof AnthropicApi.Usage anthropic) {
            return usage.getPromptTokens() + orZero(anthropic.cacheReadInputTokens())
                    + orZero(anthropic.cacheCreationInputTokens());
        }
        return usage.getPromptTokens();
    }

    /** The input tokens served from the provider's prompt cache; null when the provider reported none (not zero). */
    static Integer cachedPromptTokens(Usage usage) {
        Object nativeUsage = usage == null ? null : usage.getNativeUsage();
        if (nativeUsage instanceof OpenAiApi.Usage openAi && openAi.promptTokensDetails() != null) {
            return openAi.promptTokensDetails().cachedTokens();
        }
        if (nativeUsage instanceof AnthropicApi.Usage anthropic) {
            return anthropic.cacheReadInputTokens();
        }
        return null;
    }

    /** The counts of a work as the transcript keeps them. */
    static Map<String, Integer> counts(Usage usage) {
        if (usage == null) {
            return Map.of();
        }
        Map<String, Integer> tokens = new LinkedHashMap<>();
        Integer prompt = promptTokens(usage);
        if (prompt != null) {
            tokens.put("promptTokens", prompt);
        }
        if (usage.getCompletionTokens() != null) {
            tokens.put("completionTokens", usage.getCompletionTokens());
        }
        if (prompt != null && usage.getCompletionTokens() != null) {
            tokens.put("totalTokens", prompt + usage.getCompletionTokens());
        } else if (usage.getTotalTokens() != null) {
            tokens.put("totalTokens", usage.getTotalTokens());
        }
        Integer cached = cachedPromptTokens(usage);
        if (cached != null) {
            tokens.put("cachedPromptTokens", cached);
        }
        return tokens;
    }

    private static int orZero(Integer value) {
        return value == null ? 0 : value;
    }
}
