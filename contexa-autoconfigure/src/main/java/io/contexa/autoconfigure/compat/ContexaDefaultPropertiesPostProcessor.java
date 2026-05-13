package io.contexa.autoconfigure.compat;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.util.LinkedHashMap;
import java.util.Map;

public class ContexaDefaultPropertiesPostProcessor implements EnvironmentPostProcessor {

    static final String SOURCE_NAME = "contexaDefaultProperties";

    private static final Map<String, Object> DEFAULTS = new LinkedHashMap<>();

    static {
        DEFAULTS.put("contexa.vectorstore.pgvector.dimensions", "1536");
        DEFAULTS.put("spring.ai.vectorstore.pgvector.dimensions", "1536");
        DEFAULTS.put("spring.ai.vectorstore.pgvector.initialize-schema", "true");
        DEFAULTS.put("spring.ai.vectorstore.pgvector.schema-name", "public");
        DEFAULTS.put("spring.ai.vectorstore.pgvector.table-name", "vector_store");
        DEFAULTS.put("spring.ai.openai.embedding.options.model", "text-embedding-3-small");
        DEFAULTS.put("spring.ai.openai.embedding.options.dimensions", "1536");
    }

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        environment.getPropertySources().addLast(new MapPropertySource(SOURCE_NAME, DEFAULTS));
    }
}
