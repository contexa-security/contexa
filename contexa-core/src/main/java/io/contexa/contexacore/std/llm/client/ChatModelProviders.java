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

import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.prompt.ChatOptions;

import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The provider of a Spring AI chat model, told by the package Spring AI puts the model or its default options in
 * (Azure OpenAI before OpenAI, whose package name it contains).
 */
public final class ChatModelProviders {

    private static final List<Map.Entry<String, String>> PACKAGE_PROVIDERS = List.of(
            Map.entry(".azure.", "azure-openai"), Map.entry(".openai.", "openai"),
            Map.entry(".anthropic.", "anthropic"), Map.entry(".ollama.", "ollama"),
            Map.entry(".vertexai.", "google"), Map.entry(".google.", "google"),
            Map.entry(".bedrock.", "bedrock"), Map.entry(".mistralai.", "mistral"));

    private ChatModelProviders() {
    }

    /** The provider of the chat model, by its class and then its default options; null when neither tells. */
    public static String providerOf(ChatModel model) {
        if (model == null) {
            return null;
        }
        String provider = providerOfClass(model.getClass().getName());
        if (provider != null) {
            return provider;
        }
        ChatOptions defaults = model.getDefaultOptions();
        return defaults != null ? providerOfClass(defaults.getClass().getName()) : null;
    }

    private static String providerOfClass(String className) {
        String name = className.toLowerCase(Locale.ROOT);
        for (Map.Entry<String, String> entry : PACKAGE_PROVIDERS) {
            if (name.contains(entry.getKey())) {
                return entry.getValue();
            }
        }
        return null;
    }
}
