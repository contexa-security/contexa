package io.contexa.showcase.portal.combination;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;

/**
 * The version key of a combination record (docs/showcase/P4-설계.md 1절): the SHA-256 of every execution specification
 * field known before a run. A record is reused only under the same key, so a change of code, engine, mode, protection,
 * models, rules, scoring contract, time zone or the employee's template retires every earlier record.
 */
public final class CombinationVersions {

    private static final ObjectMapper CANONICAL = new ObjectMapper()
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    private CombinationVersions() {
    }

    public static String key(JsonNode engine, JsonNode rules, String templateId, String contractVersion) {
        Map<String, Object> fields = new TreeMap<>();
        fields.put("codeCommit", engine.path("codeCommit").asText());
        fields.put("engineVersion", engine.path("engineVersion").asText());
        fields.put("effectiveMode", engine.path("effectiveMode").asText());
        Map<String, String> protection = new TreeMap<>();
        engine.path("endpointProtection").properties()
                .forEach(entry -> protection.put(entry.getKey(), entry.getValue().asText()));
        fields.put("endpointProtection", protection);
        fields.put("chatModel", engine.path("chatModel").asText());
        fields.put("embeddingModel", engine.path("embeddingModel").asText());
        fields.put("embeddingDimensions", engine.path("embeddingDimensions").asInt());
        fields.put("timeZone", engine.path("timeZone").asText());
        fields.put("ruleVersion", rules.path("sha256").asText());
        fields.put("contractVersion", contractVersion);
        fields.put("templateId", templateId);
        fields.put("catalogVersion", CombinationCatalog.VERSION);
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(CANONICAL.writeValueAsString(fields).getBytes(StandardCharsets.UTF_8)));
        } catch (JsonProcessingException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("Version key could not be computed", e);
        }
    }
}
