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
 
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
 
import java.util.LinkedHashMap;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
 
public class ContexaDefaultPropertiesPostProcessor implements EnvironmentPostProcessor {
 
    static final String SOURCE_NAME = "contexaDefaultProperties";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        environment.getPropertySources().addLast(new MapPropertySource(SOURCE_NAME, defaults(environment)));
    }
 
    private Map<String, Object> defaults(ConfigurableEnvironment environment) {
        EmbeddingDimensionResolver.ResolvedDimension dimension =
                EmbeddingDimensionResolver.resolveForEnvironment(environment);
        String dimensionValue = Integer.toString(dimension.dimensions());
 
        Map<String, Object> defaults = new LinkedHashMap<>();
        defaults.put("contexa.vectorstore.pgvector.dimensions", dimensionValue);
        defaults.put("spring.ai.vectorstore.pgvector.dimensions", dimensionValue);
        defaults.put("spring.ai.vectorstore.pgvector.initialize-schema", "true");
        defaults.put("spring.ai.vectorstore.pgvector.schema-name", "public");
        defaults.put("spring.ai.vectorstore.pgvector.table-name", "vector_store");
        defaults.put("spring.ai.openai.embedding.options.model", EmbeddingDimensionResolver.DEFAULT_OPENAI_EMBEDDING_MODEL);
        defaults.put("spring.ai.openai.embedding.options.dimensions", dimensionValue);
        addExplicitModelSelectionDefaults(environment, defaults);
        defaults.put("management.prometheus.metrics.export.exemplars.enabled", "false");
        defaults.put("management.metrics.enable.lettuce", "false");
        return defaults;
    }

    private void addExplicitModelSelectionDefaults(
            ConfigurableEnvironment environment,
            Map<String, Object> defaults) {
        String chatPriority = environment.getProperty("contexa.llm.selection.chat.priority");
        String embeddingPriority = environment.getProperty("contexa.llm.selection.embedding.priority");
        List<String> chatProviders = providers(chatPriority);
        List<String> embeddingProviders = providers(embeddingPriority);
        if (chatProviders.size() == 1 && Set.of("openai", "anthropic", "ollama").contains(chatProviders.get(0))) {
            defaults.put("spring.ai.model.chat", chatProviders.get(0));
        }
        if (!embeddingProviders.isEmpty()
                && Set.of("openai", "ollama").contains(embeddingProviders.get(0))) {
            defaults.put("spring.ai.model.embedding", embeddingProviders.get(0));
        }
        if (!chatProviders.isEmpty() || !embeddingProviders.isEmpty()) {
            defaults.put("spring.ai.model.image", "none");
            defaults.put("spring.ai.model.moderation", "none");
            defaults.put("spring.ai.model.audio.speech", "none");
            defaults.put("spring.ai.model.audio.transcription", "none");
        }
    }

    private List<String> providers(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        return Arrays.stream(value.split(","))
                .map(String::trim)
                .map(provider -> provider.toLowerCase(Locale.ROOT))
                .filter(provider -> !provider.isBlank())
                .distinct()
                .toList();
    }
}

