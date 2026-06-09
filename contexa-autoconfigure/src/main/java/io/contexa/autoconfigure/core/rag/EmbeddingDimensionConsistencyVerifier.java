package io.contexa.autoconfigure.core.rag;

import io.contexa.autoconfigure.compat.EmbeddingDimensionResolver;
import io.contexa.autoconfigure.properties.ContexaLlmSelectionProperties;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeBinding;
import io.contexa.contexacore.std.llm.runtime.LlmRuntimeCatalog;
import io.contexa.contexacore.std.rag.properties.PgVectorStoreProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

import org.springframework.beans.factory.annotation.Qualifier;
import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class EmbeddingDimensionConsistencyVerifier implements SmartInitializingSingleton {

    private static final Pattern VECTOR_TYPE_PATTERN = Pattern.compile("vector\\((\\d+)\\)");

    private final PgVectorStoreProperties vectorStoreProperties;
    private final ContexaLlmSelectionProperties selectionProperties;
    private final Environment environment;
    private final LlmRuntimeCatalog runtimeCatalog;
    private final DataSource dataSource;

    public EmbeddingDimensionConsistencyVerifier(
            PgVectorStoreProperties vectorStoreProperties,
            ContexaLlmSelectionProperties selectionProperties,
            Environment environment,
            LlmRuntimeCatalog runtimeCatalog,
            @Qualifier("contexaDataSource") DataSource dataSource) {
        this.vectorStoreProperties = vectorStoreProperties;
        this.selectionProperties = selectionProperties;
        this.environment = environment;
        this.runtimeCatalog = runtimeCatalog;
        this.dataSource = dataSource;
    }

    @Override
    public void afterSingletonsInstantiated() {
        EmbeddingDimensionResolver.ResolvedDimension expected = resolveActiveDimension();
        int configuredDimension = vectorStoreProperties.getDimensions();

        if (!expected.modelKnown() && !expected.explicit()) {
            throw new IllegalStateException("""
                    Unknown embedding model dimension. Configure an explicit embedding/vector dimension before RAG starts.
                    selectedProvider=%s, selectedModel=%s, configuredPgVectorDimension=%d.
                    Set contexa.llm.embedding.dimensions and contexa.vectorstore.pgvector.dimensions to the model output dimension.
                    """.formatted(expected.provider(), expected.modelId(), configuredDimension).trim());
        }

        if (configuredDimension != expected.dimensions()) {
            throw new IllegalStateException("""
                    Embedding dimension mismatch before vector storage starts.
                    selectedProvider=%s, selectedModel=%s, expectedDimension=%d, configuredPgVectorDimension=%d.
                    Keep contexa.vectorstore.pgvector.dimensions, spring.ai.vectorstore.pgvector.dimensions, and provider embedding dimensions identical.
                    Existing vectors must be regenerated when the dimension changes.
                    """.formatted(expected.provider(), expected.modelId(), expected.dimensions(), configuredDimension).trim());
        }

        OptionalInt existingTableDimension = readExistingPgVectorTableDimension();
        if (existingTableDimension.isPresent() && existingTableDimension.getAsInt() != configuredDimension) {
            throw new IllegalStateException("""
                    Existing vector_store table dimension does not match active embedding profile.
                    selectedProvider=%s, selectedModel=%s, configuredPgVectorDimension=%d, existingTableDimension=%d.
                    Recreate the vector table or re-embed existing documents before starting with this embedding profile.
                    """.formatted(expected.provider(), expected.modelId(), configuredDimension, existingTableDimension.getAsInt()).trim());
        }

        log.info("Embedding vector dimension verified: provider={}, model={}, dimension={}, source={}",
                expected.provider(), expected.modelId(), configuredDimension, expected.source());
    }

    private EmbeddingDimensionResolver.ResolvedDimension resolveActiveDimension() {
        Optional<LlmRuntimeBinding> selectedBinding = selectEmbeddingBinding();
        if (selectedBinding.isPresent()) {
            LlmRuntimeBinding binding = selectedBinding.get();
            String provider = binding.getProvider();
            String model = resolveModel(provider, binding.getModelId());
            return EmbeddingDimensionResolver.resolveForRuntime(environment, provider, model);
        }
        return EmbeddingDimensionResolver.resolveForEnvironment(environment);
    }

    private Optional<LlmRuntimeBinding> selectEmbeddingBinding() {
        if (runtimeCatalog == null) {
            return Optional.empty();
        }
        List<LlmRuntimeBinding> bindings = runtimeCatalog.getEmbeddingBindings();
        if (bindings == null || bindings.isEmpty()) {
            return Optional.empty();
        }
        List<String> providers = parsePriority(selectionProperties.getEmbedding().getPriority());
        if (providers.size() > 1) {
            throw new IllegalStateException(
                    "Embedding runtime must use exactly one fixed provider. "
                            + "Dynamic provider priority is not allowed for dimension-bound vector storage: "
                            + selectionProperties.getEmbedding().getPriority());
        }
        for (String provider : providers) {
            Optional<LlmRuntimeBinding> match = bindings.stream()
                    .filter(binding -> provider.equals(normalize(binding.getProvider())))
                    .findFirst();
            if (match.isPresent()) {
                return match;
            }
        }
        return Optional.of(bindings.get(0));
    }

    private String resolveModel(String provider, String bindingModelId) {
        Optional<String> configuredModel = EmbeddingDimensionResolver.configuredModelForProvider(environment, provider);
        if (configuredModel.isPresent()) {
            return configuredModel.get();
        }
        if (StringUtils.hasText(bindingModelId) && !looksLikeSpringBeanName(bindingModelId)) {
            return bindingModelId.trim();
        }
        return EmbeddingDimensionResolver.modelForProvider(environment, provider);
    }

    private boolean looksLikeSpringBeanName(String value) {
        String normalized = normalize(value);
        return normalized.endsWith("embeddingmodel")
                || normalized.endsWith("embedding")
                || normalized.contains("embeddingmodel#");
    }

    private List<String> parsePriority(String priority) {
        if (!StringUtils.hasText(priority)) {
            return List.of();
        }
        return Arrays.stream(priority.split(","))
                .map(this::normalize)
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    private OptionalInt readExistingPgVectorTableDimension() {
        if (dataSource == null) {
            return OptionalInt.empty();
        }
        try (Connection connection = dataSource.getConnection()) {
            String productName = connection.getMetaData().getDatabaseProductName();
            if (productName == null || !productName.toLowerCase(Locale.ROOT).contains("postgres")) {
                return OptionalInt.empty();
            }
            String schema = environment.getProperty("spring.ai.vectorstore.pgvector.schema-name", "public");
            String table = environment.getProperty("spring.ai.vectorstore.pgvector.table-name", "vector_store");
            String relation = quoteIdentifier(schema) + "." + quoteIdentifier(table);
            try (PreparedStatement statement = connection.prepareStatement("""
                    select format_type(a.atttypid, a.atttypmod)
                    from pg_attribute a
                    where a.attrelid = to_regclass(?)
                      and a.attname = 'embedding'
                      and not a.attisdropped
                    """)) {
                statement.setString(1, relation);
                try (ResultSet resultSet = statement.executeQuery()) {
                    if (!resultSet.next()) {
                        return OptionalInt.empty();
                    }
                    return parseVectorDimension(resultSet.getString(1));
                }
            }
        }
        catch (SQLException ex) {
            throw new IllegalStateException("Unable to verify pgvector table dimension before RAG starts: " + ex.getMessage(), ex);
        }
    }

    private OptionalInt parseVectorDimension(String formattedType) {
        if (!StringUtils.hasText(formattedType)) {
            return OptionalInt.empty();
        }
        Matcher matcher = VECTOR_TYPE_PATTERN.matcher(formattedType.trim().toLowerCase(Locale.ROOT));
        if (!matcher.matches()) {
            return OptionalInt.empty();
        }
        return OptionalInt.of(Integer.parseInt(matcher.group(1)));
    }

    private String quoteIdentifier(String identifier) {
        if (!StringUtils.hasText(identifier)) {
            throw new IllegalStateException("pgvector schema/table identifier must not be blank");
        }
        return "\"" + identifier.trim().replace("\"", "\"\"") + "\"";
    }

    private String normalize(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }
}
