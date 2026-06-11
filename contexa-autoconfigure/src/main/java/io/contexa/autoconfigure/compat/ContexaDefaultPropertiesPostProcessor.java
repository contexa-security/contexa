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
import java.util.Map;
 
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
        defaults.put("management.prometheus.metrics.export.exemplars.enabled", "false");
        defaults.put("management.metrics.enable.lettuce", "false");
        return defaults;
    }
}

