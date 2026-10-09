package io.contexa.showcase.portal.spec;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;

/**
 * Canonical hash of an {@link ExecutionSpec}: SHA-256 (lowercase hex) of compact UTF-8 JSON in which every object
 * key, nested ones included, is sorted lexicographically and absent optional values are empty strings.
 */
public final class ExecutionSpecHasher {

    private static final ObjectMapper CANONICAL_JSON = new ObjectMapper()
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    private ExecutionSpecHasher() {
    }

    public static String hash(ExecutionSpec spec) {
        return sha256(canonicalJson(spec));
    }

    /**
     * The measurement setting (W5, V-13): the specification without the per-employee template and the system prompt
     * hash, plus the version the templates were learned under ({@code templateVersion}, TemplateVersions). Runs of
     * one measurement protocol share it although each protagonist's runs clone a different template.
     */
    public static String settingHash(ExecutionSpec spec, String templateVersion) {
        Map<String, Object> fields = new TreeMap<>();
        fields.put("codeCommit", spec.codeCommit());
        fields.put("engineVersion", spec.engineVersion());
        fields.put("effectiveMode", spec.effectiveMode());
        fields.put("endpointProtection", new TreeMap<>(spec.endpointProtection()));
        fields.put("chatModel", spec.chatModel());
        fields.put("embeddingModel", spec.embeddingModel());
        fields.put("embeddingDimensions", spec.embeddingDimensions());
        fields.put("ruleVersion", spec.ruleVersion());
        fields.put("contractVersion", spec.contractVersion() == null ? "" : spec.contractVersion());
        fields.put("timeZone", spec.timeZone());
        fields.put("templateVersion", templateVersion == null ? "" : templateVersion);
        if (spec.modelSettings() != null) {
            fields.put("modelSettings", sortedCopy(spec.modelSettings()));
        }
        try {
            return sha256(CANONICAL_JSON.writeValueAsString(fields));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Measurement setting could not be serialized", e);
        }
    }

    static String canonicalJson(ExecutionSpec spec) {
        Map<String, Object> fields = new TreeMap<>();
        fields.put("codeCommit", spec.codeCommit());
        fields.put("engineVersion", spec.engineVersion());
        fields.put("effectiveMode", spec.effectiveMode());
        fields.put("endpointProtection", new TreeMap<>(spec.endpointProtection()));
        fields.put("chatModel", spec.chatModel());
        fields.put("embeddingModel", spec.embeddingModel());
        fields.put("embeddingDimensions", spec.embeddingDimensions());
        fields.put("promptHash", spec.promptHash());
        fields.put("templateId", spec.templateId() == null ? "" : spec.templateId());
        fields.put("ruleVersion", spec.ruleVersion());
        fields.put("contractVersion", spec.contractVersion() == null ? "" : spec.contractVersion());
        fields.put("timeZone", spec.timeZone());
        // Absent for specifications recorded before the model settings were reported, so their hashes stay as they were.
        if (spec.modelSettings() != null) {
            fields.put("modelSettings", sortedCopy(spec.modelSettings()));
        }
        try {
            return CANONICAL_JSON.writeValueAsString(fields);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Execution spec could not be serialized", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static Object sortedCopy(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> sorted = new TreeMap<>();
            ((Map<String, Object>) map).forEach((key, inner) -> sorted.put(key, sortedCopy(inner)));
            return sorted;
        }
        return value;
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
