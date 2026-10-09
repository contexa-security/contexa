package io.contexa.showcase.portal.scenario;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * Scenario definitions packaged with the portal under {@code scenarios/*.json}, each with the SHA-256 of its canonical
 * form (W2-5): the JSON with object keys sorted and no whitespace, in UTF-8, so the hash does not depend on how the file
 * was checked out or indented and anyone can recompute it from the published definition.
 */
public class ScenarioCatalog {

    /** How the case hash is computed, as the visitor API states it. */
    public static final String CANONICAL_FORM = "SHA-256 of the case JSON with object keys sorted and no whitespace, "
            + "UTF-8";

    private static final ObjectMapper CANONICAL = JsonMapper.builder()
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
            .build();

    private final Map<String, ScenarioDefinition> scenarios = new TreeMap<>();
    private final Map<String, String> hashes = new TreeMap<>();

    public ScenarioCatalog(ObjectMapper json) throws IOException {
        Resource[] resources = new PathMatchingResourcePatternResolver().getResources("classpath*:scenarios/*.json");
        for (Resource resource : resources) {
            byte[] bytes;
            try (InputStream in = resource.getInputStream()) {
                bytes = in.readAllBytes();
            }
            ScenarioDefinition scenario = json.readValue(bytes, ScenarioDefinition.class);
            if (scenarios.put(scenario.key(), scenario) != null) {
                throw new IllegalStateException("Duplicate scenario key " + scenario.key());
            }
            hashes.put(scenario.key(), hash(canonical(bytes)));
        }
    }

    public Optional<ScenarioDefinition> find(String key) {
        return Optional.ofNullable(scenarios.get(key));
    }

    public Collection<ScenarioDefinition> all() {
        return scenarios.values();
    }

    /** The SHA-256 of a packaged case's canonical form ({@link #CANONICAL_FORM}). */
    public Optional<String> sha256(String key) {
        return Optional.ofNullable(hashes.get(key));
    }

    static String canonical(byte[] definition) throws IOException {
        return CANONICAL.writeValueAsString(CANONICAL.readValue(definition, Object.class));
    }

    static String hash(String text) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
