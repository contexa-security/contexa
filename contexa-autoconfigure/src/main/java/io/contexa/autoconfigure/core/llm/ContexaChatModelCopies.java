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

import io.contexa.contexacore.std.llm.client.ProviderAwareChatOptionsFactory;
import io.contexa.contexacore.std.llm.model.ChatModelVariants;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.anthropic.AnthropicChatOptions;
import org.springframework.ai.anthropic.api.AnthropicCacheOptions;
import org.springframework.ai.anthropic.api.AnthropicCacheStrategy;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.core.env.Environment;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;

/**
 * R-9: the OpenAI and Anthropic chat models Contexa calls are instances of its own. Contexa sets in a model's default
 * options what the model it runs takes (no sampling value for a model that refuses one, the token limit field of OpenAI's
 * reasoning models, no thinking field the provider refused, Anthropic's system prompt cache), and Spring AI merges the
 * defaults into every request the model sends. Setting them in the application's chat model bean changed the
 * application's own calls. So Contexa calls a copy of the bean, made once: the application's client, retry, observation
 * and model, with default options of its own. The bean keeps what the application gave it. Any other chat model, and one
 * that cannot be copied, is called as it is, and Contexa sets nothing in its default options: its calls ask for what
 * they need in their requests ({@code ProviderAwareChatOptionsFactory.normalizeModelDefaultOptionsInPlace}).
 */
@Slf4j
public final class ContexaChatModelCopies {

    private static final String OPENAI_CHAT_MODEL = "org.springframework.ai.openai.OpenAiChatModel";
    private static final String ANTHROPIC_CHAT_MODEL = "org.springframework.ai.anthropic.AnthropicChatModel";

    private final Environment environment;
    private final Map<ChatModel, ChatModel> copies = Collections.synchronizedMap(new WeakHashMap<>());

    public ContexaChatModelCopies(Environment environment) {
        this.environment = environment;
    }

    /** Contexa's instance of the chat model: its copy, made the first time it is asked for, or the model itself. */
    public ChatModel of(ChatModel model) {
        if (model == null || !adjusted(model)) {
            return model;
        }
        return copies.computeIfAbsent(model, this::copy);
    }

    /** The chat models whose default options Contexa sets for its calls. */
    private static boolean adjusted(ChatModel model) {
        String type = model.getClass().getName();
        return OPENAI_CHAT_MODEL.equals(type) || ANTHROPIC_CHAT_MODEL.equals(type);
    }

    private ChatModel copy(ChatModel model) {
        ChatModel copy = ChatModelVariants.copyOf(model).orElse(null);
        if (copy == null) {
            log.error("[ContexaChatModels] No copy of the chat model {} could be made: Contexa calls it as it is, with "
                    + "the default options the application set", model);
            return model;
        }
        ProviderAwareChatOptionsFactory.normalizeModelDefaultOptionsInPlace(copy);
        if (ANTHROPIC_CHAT_MODEL.equals(copy.getClass().getName()) && systemPromptCache()) {
            AnthropicDefaults.markSystemPrompt(copy);
        }
        return copy;
    }

    /** contexa.llm.model-capabilities.anthropic.system-prompt-cache, on unless switched off. */
    private boolean systemPromptCache() {
        return environment == null
                || AnthropicChatModelOptionsAutoConfiguration.capabilities(environment).isSystemPromptCache();
    }

    /** Kept apart, so that an application without Anthropic's library never loads its classes. */
    private static final class AnthropicDefaults {

        /**
         * Anthropic caches only the prompt a request marks, so the system prompt of Contexa's calls is marked when no
         * cache strategy is configured. The model keeps its defaults in a field it only hands out as copies.
         */
        static void markSystemPrompt(ChatModel copy) {
            Field field = ReflectionUtils.findField(AnthropicChatModel.class, "defaultOptions");
            if (field == null) {
                return;
            }
            ReflectionUtils.makeAccessible(field);
            if (ReflectionUtils.getField(field, copy) instanceof AnthropicChatOptions defaults) {
                AnthropicCacheOptions cache = defaults.getCacheOptions();
                if (cache == null || cache.getStrategy() == AnthropicCacheStrategy.NONE) {
                    defaults.setCacheOptions(AnthropicCacheOptions.builder()
                            .strategy(AnthropicCacheStrategy.SYSTEM_ONLY).build());
                }
            }
        }
    }
}
