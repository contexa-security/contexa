package io.contexa.demo.comparison.attestation.source.impl;

import io.contexa.demo.RuntimeLabApplication;
import io.contexa.demo.comparison.attestation.dto.ExecutionEnvironment;
import io.contexa.demo.comparison.attestation.source.ExecutionEnvironmentQuery;
import io.contexa.demo.comparison.manifest.source.NativeConfigurationQuery;
import io.contexa.demo.comparison.manifest.source.RagInventoryQuery;
import io.contexa.demo.observation.health.service.CollectorRegistry;
import io.contexa.demo.shared.document.DocumentCodec;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.system.ApplicationHome;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Component;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

@Component
@Profile({"baseline", "contexa"})
public class StoredExecutionEnvironmentQuery implements ExecutionEnvironmentQuery {

    private static final List<String> CONFIGURATION_KEYS = List.of(
            "lab.role", "contexa.enabled", "contexa.infrastructure.mode", "contexa.zero-trust.mode",
            "lab.chat.provider", "lab.chat.model", "lab.embedding.provider", "lab.embedding.model",
            "lab.embedding.dimensions", "spring.ai.model.chat", "spring.ai.model.embedding",
            "spring.ai.openai.chat.options.model", "spring.ai.openai.chat.options.temperature",
            "spring.ai.openai.chat.options.max-completion-tokens", "spring.ai.ollama.chat.options.model",
            "spring.ai.ollama.chat.options.temperature", "spring.ai.ollama.chat.options.num-predict",
            "contexa.llm.selection.chat.priority",
            "contexa.llm.model-capabilities.openai.max-completion-token-patterns",
            "contexa.llm.model-capabilities.openai.default-sampling-only-patterns",
            "contexa.llm.model-capabilities.ollama.disable-thinking-patterns");
    private static final List<String> RESOURCES = List.of("application.yml", "application-baseline.yml",
            "application-contexa.yml", "application-persistent.yml");

    private final Environment environment;
    private final JdbcOperations jdbc;
    private final DocumentCodec documents;
    private final CollectorRegistry collectors;
    private final String artifactHash;
    private final Map<String, String> resources;
    private final NativeConfigurationQuery nativeConfiguration;
    private final RagInventoryQuery ragInventory;

    public StoredExecutionEnvironmentQuery(Environment environment,
            @Qualifier("jdbcTemplate") JdbcOperations jdbc, DocumentCodec documents, CollectorRegistry collectors,
            NativeConfigurationQuery nativeConfiguration, RagInventoryQuery ragInventory) {
        this.environment = environment;
        this.jdbc = jdbc;
        this.documents = documents;
        this.collectors = collectors;
        this.artifactHash = artifactHash();
        this.resources = resourceHashes();
        this.nativeConfiguration = nativeConfiguration;
        this.ragInventory = ragInventory;
    }

    @Override
    public ExecutionEnvironment capture() {
        Map<String, String> selected = new TreeMap<>();
        for (String key : CONFIGURATION_KEYS) {
            String value = environment.getProperty(key);
            if (value != null) {
                selected.put(key, value);
            }
        }
        var migrations = jdbc.queryForList("""
                select installed_rank,version,script,checksum,success from lab.flyway_schema_history
                order by installed_rank
                """);
        return new ExecutionEnvironment(collectors.instanceId(), artifactHash,
                artifactHash == null ? "UNAVAILABLE" : "CAPTURED",
                Map.copyOf(selected), resources, documents.hash(documents.write(migrations)),
                nativeConfiguration.capture(), ragInventory.capture());
    }

    private String artifactHash() {
        var source = new ApplicationHome(RuntimeLabApplication.class).getSource();
        if (source == null || !source.isFile()) {
            return null;
        }
        try (InputStream input = Files.newInputStream(source.toPath())) {
            return digest(input);
        } catch (IOException unavailable) {
            return null;
        }
    }

    private Map<String, String> resourceHashes() {
        Map<String, String> hashes = new TreeMap<>();
        for (String name : RESOURCES) {
            try (InputStream input = new ClassPathResource(name).getInputStream()) {
                hashes.put(name, digest(input));
            } catch (IOException unavailable) {
                // Missing resources remain absent rather than receiving a fabricated hash.
            }
        }
        return Map.copyOf(hashes);
    }

    private String digest(InputStream input) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            new DigestInputStream(input, digest).transferTo(OutputStream.nullOutputStream());
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException(unavailable);
        }
    }
}
