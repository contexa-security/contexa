package io.contexa.autoconfigure.compat;

import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertySource;
import org.springframework.util.StringUtils;

import java.util.Locale;
import java.util.Optional;

public final class EmbeddingDimensionResolver {

    public static final int PRODUCT_DEFAULT_DIMENSIONS = 1024;
    public static final String DEFAULT_OPENAI_EMBEDDING_MODEL = "text-embedding-3-small";
    public static final String DEFAULT_OLLAMA_EMBEDDING_MODEL = "mxbai-embed-large";

    private static final String DEFAULT_SOURCE_NAME = ContexaDefaultPropertiesPostProcessor.SOURCE_NAME;

    private EmbeddingDimensionResolver() {
    }

    public static ResolvedDimension resolveForEnvironment(Environment environment) {
        String provider = firstProvider(environment);
        String model = modelForProvider(environment, provider);
        return resolve(environment, provider, model, false);
    }

    public static ResolvedDimension resolveForRuntime(Environment environment, String provider, String modelId) {
        String normalizedProvider = normalize(provider);
        if (!StringUtils.hasText(normalizedProvider)) {
            normalizedProvider = firstProvider(environment);
        }
        String normalizedModel = normalize(modelId);
        if (!StringUtils.hasText(normalizedModel)) {
            normalizedModel = modelForProvider(environment, normalizedProvider);
        }
        return resolve(environment, normalizedProvider, normalizedModel, true);
    }

    private static ResolvedDimension resolve(
            Environment environment,
            String provider,
            String model,
            boolean ignoreContexaDefaults) {

        Optional<Integer> vectorStoreDimensions = readInt(environment,
                ignoreContexaDefaults,
                "contexa.vectorstore.pgvector.dimensions",
                "spring.ai.vectorstore.pgvector.dimensions");
        if (vectorStoreDimensions.isPresent()) {
            return new ResolvedDimension(provider, model, vectorStoreDimensions.get(), "vector-store-property", true, true);
        }

        Optional<Integer> globalDimensions = readInt(environment,
                ignoreContexaDefaults,
                "contexa.llm.embedding.dimensions");
        if (globalDimensions.isPresent()) {
            return new ResolvedDimension(provider, model, globalDimensions.get(), "contexa-embedding-property", true, true);
        }

        Optional<Integer> providerDimensions = readProviderDimensions(environment, provider, ignoreContexaDefaults);
        if (providerDimensions.isPresent()) {
            return new ResolvedDimension(provider, model, providerDimensions.get(), provider + "-embedding-property", true, true);
        }

        ModelDimensionPolicy policy = policyFor(provider, model);
        if (policy.known()) {
            return new ResolvedDimension(provider, model, policy.defaultDimensions(), policy.source(), false, true);
        }

        return new ResolvedDimension(provider, model, PRODUCT_DEFAULT_DIMENSIONS, "product-default-unknown-model", false, false);
    }

    private static Optional<Integer> readProviderDimensions(Environment environment, String provider, boolean ignoreContexaDefaults) {
        String normalizedProvider = normalize(provider);
        if ("openai".equals(normalizedProvider)) {
            return readInt(environment, ignoreContexaDefaults, "spring.ai.openai.embedding.options.dimensions");
        }
        if ("ollama".equals(normalizedProvider)) {
            return readInt(environment,
                    ignoreContexaDefaults,
                    "contexa.llm.embedding.ollama.dimensions",
                    "spring.ai.ollama.embedding.options.dimensions");
        }
        return Optional.empty();
    }

    private static ModelDimensionPolicy policyFor(String provider, String modelId) {
        String providerKey = normalize(provider);
        String modelKey = normalize(modelId);

        if ("openai".equals(providerKey)) {
            if (!StringUtils.hasText(modelKey) || DEFAULT_OPENAI_EMBEDDING_MODEL.equals(modelKey)) {
                return ModelDimensionPolicy.known(PRODUCT_DEFAULT_DIMENSIONS, "openai-text-embedding-3-small-product-default");
            }
            if ("text-embedding-3-large".equals(modelKey)) {
                return ModelDimensionPolicy.known(PRODUCT_DEFAULT_DIMENSIONS, "openai-text-embedding-3-large-product-default");
            }
            if ("text-embedding-ada-002".equals(modelKey)) {
                return ModelDimensionPolicy.known(1536, "openai-ada-fixed-default");
            }
            if (modelKey.startsWith("text-embedding-3")) {
                return ModelDimensionPolicy.known(PRODUCT_DEFAULT_DIMENSIONS, "openai-text-embedding-3-product-default");
            }
            return ModelDimensionPolicy.unknown();
        }

        if ("ollama".equals(providerKey)) {
            if (!StringUtils.hasText(modelKey) || DEFAULT_OLLAMA_EMBEDDING_MODEL.equals(modelKey)) {
                return ModelDimensionPolicy.known(PRODUCT_DEFAULT_DIMENSIONS, "ollama-mxbai-embed-large-default");
            }
            if ("bge-m3".equals(modelKey)) {
                return ModelDimensionPolicy.known(PRODUCT_DEFAULT_DIMENSIONS, "ollama-bge-m3-default");
            }
            return ModelDimensionPolicy.unknown();
        }

        return ModelDimensionPolicy.unknown();
    }

    private static String firstProvider(Environment environment) {
        String priority = firstText(environment,
                "contexa.llm.selection.embedding.priority",
                "contexa.llm.embedding-model-priority")
                .orElse("openai");
        for (String part : priority.split(",")) {
            String provider = normalize(part);
            if (StringUtils.hasText(provider)) {
                return provider;
            }
        }
        return "openai";
    }

    public static String modelForProvider(Environment environment, String provider) {
        String normalizedProvider = normalize(provider);
        if ("openai".equals(normalizedProvider)) {
            return configuredModelForProvider(environment, normalizedProvider)
                    .orElse(DEFAULT_OPENAI_EMBEDDING_MODEL);
        }
        if ("ollama".equals(normalizedProvider)) {
            return configuredModelForProvider(environment, normalizedProvider)
                    .orElse(DEFAULT_OLLAMA_EMBEDDING_MODEL);
        }
        return "";
    }

    public static Optional<String> configuredModelForProvider(Environment environment, String provider) {
        String normalizedProvider = normalize(provider);
        if ("openai".equals(normalizedProvider)) {
            return firstText(environment, "spring.ai.openai.embedding.options.model");
        }
        if ("ollama".equals(normalizedProvider)) {
            return firstText(environment,
                    "contexa.llm.embedding.ollama.model",
                    "spring.ai.ollama.embedding.options.model");
        }
        return Optional.empty();
    }

    private static Optional<String> firstText(Environment environment, String... keys) {
        for (String key : keys) {
            String value = environment.getProperty(key);
            if (StringUtils.hasText(value)) {
                return Optional.of(value.trim());
            }
        }
        return Optional.empty();
    }

    private static Optional<Integer> readInt(Environment environment, boolean ignoreContexaDefaults, String... keys) {
        for (String key : keys) {
            String value = readProperty(environment, key, ignoreContexaDefaults);
            if (!StringUtils.hasText(value)) {
                continue;
            }
            try {
                return Optional.of(Integer.parseInt(value.trim()));
            }
            catch (NumberFormatException ex) {
                throw new IllegalStateException("Embedding dimension property '" + key + "' must be an integer: " + value, ex);
            }
        }
        return Optional.empty();
    }

    private static String readProperty(Environment environment, String key, boolean ignoreContexaDefaults) {
        if (!ignoreContexaDefaults || !(environment instanceof ConfigurableEnvironment configurableEnvironment)) {
            return environment.getProperty(key);
        }

        for (PropertySource<?> source : configurableEnvironment.getPropertySources()) {
            if (DEFAULT_SOURCE_NAME.equals(source.getName())) {
                continue;
            }
            Object value = source.getProperty(key);
            if (value != null) {
                return environment.resolvePlaceholders(String.valueOf(value));
            }
        }
        return null;
    }

    private static String normalize(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }

    public record ResolvedDimension(
            String provider,
            String modelId,
            int dimensions,
            String source,
            boolean explicit,
            boolean modelKnown) {
    }

    private record ModelDimensionPolicy(int defaultDimensions, String source, boolean known) {
        static ModelDimensionPolicy known(int defaultDimensions, String source) {
            return new ModelDimensionPolicy(defaultDimensions, source, true);
        }

        static ModelDimensionPolicy unknown() {
            return new ModelDimensionPolicy(PRODUCT_DEFAULT_DIMENSIONS, "unknown-model", false);
        }
    }
}
