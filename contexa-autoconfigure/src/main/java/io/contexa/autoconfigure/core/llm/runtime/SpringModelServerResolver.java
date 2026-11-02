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
package io.contexa.autoconfigure.core.llm.runtime;

import io.contexa.contexacore.std.llm.gate.CallKind;
import io.contexa.contexacore.std.llm.gate.ModelServer;
import io.contexa.contexacore.std.llm.gate.ModelServerResolver;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The model server of a Spring AI model: the address Contexa built it with (its own Ollama connection), else the
 * provider's base URL as Spring AI reads it, else the provider's public endpoint.
 */
public class SpringModelServerResolver implements ModelServerResolver {

    private static final List<Map.Entry<String, String>> PROVIDERS = List.of(
            Map.entry("azure", "azure-openai"), Map.entry("openai", "openai"), Map.entry("anthropic", "anthropic"),
            Map.entry("ollama", "ollama"), Map.entry("vertexai", "google"), Map.entry("google", "google"),
            Map.entry("bedrock", "bedrock"), Map.entry("mistral", "mistral"));

    private final Environment environment;
    private final Map<Object, ModelServer> servers = Collections.synchronizedMap(new IdentityHashMap<>());
    private final Map<Object, String> modelNames = Collections.synchronizedMap(new IdentityHashMap<>());

    public SpringModelServerResolver(Environment environment) {
        this.environment = environment;
    }

    /** Records the server and the model of a model built with a known address. */
    public void register(Object model, String provider, String baseUrl, String modelName) {
        if (model == null) {
            return;
        }
        servers.put(model, ModelServer.of(provider, baseUrl));
        if (StringUtils.hasText(modelName)) {
            modelNames.put(model, modelName.trim());
        }
    }

    @Override
    public ModelServer resolve(Object model, CallKind kind) {
        ModelServer known = servers.get(model);
        if (known != null) {
            return known;
        }
        String provider = providerOf(model);
        return ModelServer.of(provider, baseUrlOf(provider, kind));
    }

    @Override
    public String embeddingModelName(Object embeddingModel) {
        String known = modelNames.get(embeddingModel);
        if (known != null) {
            return known;
        }
        return switch (providerOf(embeddingModel)) {
            case "ollama" -> property("spring.ai.ollama.embedding.options.model", "spring.ai.ollama.embedding.model");
            case "openai" -> property("spring.ai.openai.embedding.options.model");
            case "azure-openai" -> property("spring.ai.azure.openai.embedding.options.deployment-name");
            default -> null;
        };
    }

    static String providerOf(Object model) {
        if (model == null) {
            return "unknown";
        }
        String name = model.getClass().getName().toLowerCase(Locale.ROOT);
        for (Map.Entry<String, String> entry : PROVIDERS) {
            if (name.contains("." + entry.getKey())) {
                return entry.getValue();
            }
        }
        return model.getClass().getSimpleName().toLowerCase(Locale.ROOT);
    }

    private String baseUrlOf(String provider, CallKind kind) {
        boolean embedding = kind == CallKind.EMBEDDING;
        return switch (provider) {
            case "ollama" -> orDefault(property("spring.ai.ollama.base-url"), "http://localhost:11434");
            case "openai" -> orDefault(embedding
                    ? property("spring.ai.openai.embedding.base-url", "spring.ai.openai.base-url")
                    : property("spring.ai.openai.chat.base-url", "spring.ai.openai.base-url"), "https://api.openai.com");
            case "anthropic" -> orDefault(property("spring.ai.anthropic.base-url"), "https://api.anthropic.com");
            case "azure-openai" -> property("spring.ai.azure.openai.endpoint");
            case "mistral" -> orDefault(property("spring.ai.mistralai.base-url"), "https://api.mistral.ai");
            default -> null;
        };
    }

    private String property(String... keys) {
        if (environment == null) {
            return null;
        }
        for (String key : keys) {
            String value = environment.getProperty(key);
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    private static String orDefault(String value, String fallback) {
        return StringUtils.hasText(value) ? value : fallback;
    }
}
