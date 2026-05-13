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
        return defaults;
    }
}
