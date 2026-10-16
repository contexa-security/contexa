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
package io.contexa.contexacore.std.llm.client;

import org.springframework.ai.chat.metadata.Usage;

/**
 * The token counts of a provider's usage, counted the same way for every provider. Spring AI's prompt tokens are
 * Anthropic's input tokens alone, since Anthropic counts its prompt cache reads and writes apart, while OpenAI's include
 * the cached tokens; the prompt tokens here are all the input tokens of the call, as OpenAI counts them. The provider's
 * own usage object is read by its accessors, so no provider library is needed.
 */
public final class ProviderUsage {

    private ProviderUsage() {
    }

    /** Every input token of the call: Anthropic's input tokens with its cache reads and writes; else Spring AI's. */
    public static Integer promptTokens(Usage usage) {
        if (usage == null || usage.getPromptTokens() == null) {
            return null;
        }
        Integer reads = cacheReadTokens(usage);
        Integer writes = cacheWriteTokens(usage);
        if (reads == null && writes == null) {
            return usage.getPromptTokens();
        }
        return usage.getPromptTokens() + (reads != null ? reads : 0) + (writes != null ? writes : 0);
    }

    /** The prompt tokens above and the completion tokens; else Spring AI's total. */
    public static Integer totalTokens(Usage usage) {
        if (usage == null) {
            return null;
        }
        Integer prompt = promptTokens(usage);
        if (prompt == null || prompt.equals(usage.getPromptTokens())) {
            return usage.getTotalTokens();
        }
        return usage.getCompletionTokens() != null ? prompt + usage.getCompletionTokens() : prompt;
    }

    /** Anthropic's prompt cache reads; null for a provider that reports none this way. */
    public static Integer cacheReadTokens(Usage usage) {
        return nativeInteger(usage != null ? usage.getNativeUsage() : null, "cacheReadInputTokens");
    }

    /** Anthropic's prompt cache writes, which cost more than the input tokens; null when not reported. */
    public static Integer cacheWriteTokens(Usage usage) {
        return nativeInteger(usage != null ? usage.getNativeUsage() : null, "cacheCreationInputTokens");
    }

    /** The reasoning tokens OpenAI counts inside its completion tokens; null when not reported. */
    public static Integer reasoningTokens(Usage usage) {
        Object nativeUsage = usage != null ? usage.getNativeUsage() : null;
        return nativeInteger(nativeValue(nativeUsage, "completionTokenDetails"), "reasoningTokens");
    }

    private static Integer nativeInteger(Object source, String accessor) {
        return nativeValue(source, accessor) instanceof Number number ? number.intValue() : null;
    }

    private static Object nativeValue(Object source, String accessor) {
        if (source == null) {
            return null;
        }
        try {
            return source.getClass().getMethod(accessor).invoke(source);
        } catch (ReflectiveOperationException | RuntimeException e) {
            return null;
        }
    }
}
