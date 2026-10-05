package io.contexa.showcase.portal.template;

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
 * The versions a template is learned under (ADR-23 template lifetime): the SHA-256 of the code commit, the engine
 * version, the effective Zero Trust mode, the endpoint protection, the chat and embedding models, the time zone and the
 * company data. A template learned under other versions no longer matches what the engine would learn now, so runs do
 * not clone it and a new template is learned instead (docs/showcase/계획대조-검수.md N-8).
 */
public final class TemplateVersions {

    private static final ObjectMapper CANONICAL = new ObjectMapper()
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    private TemplateVersions() {
    }

    /**
     * @param engine  control D's engine description ({@code /internal/engine})
     * @param company the business workload's company description ({@code /internal/company})
     */
    public static String key(JsonNode engine, JsonNode company) {
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
        fields.put("companyData", company.path("dataSha256").asText());
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(CANONICAL.writeValueAsString(fields).getBytes(StandardCharsets.UTF_8)));
        } catch (JsonProcessingException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("Template version key could not be computed", e);
        }
    }
}
