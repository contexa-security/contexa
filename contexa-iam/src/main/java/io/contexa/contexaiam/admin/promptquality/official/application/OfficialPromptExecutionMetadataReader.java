package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public final class OfficialPromptExecutionMetadataReader {

    private static final Set<String> SELECTED_KEYS = Set.of(
            "requestId", "correlationId", "promptHash", "systemPromptHash", "userPromptHash", "contextHash",
            "rawPromptHash", "rawSystemPromptHash", "rawUserPromptHash",
            "protectableResourceId", "resourceId", "endpointKey", "promptContractVersion", "modelProfile",
            "promptCompressionApplied", "compressionApplied", "promptRawTruthParity",
            "promptViewTransformationMode", "transformationMode",
            "defaultBudgetProfile", "promptBudgetProfile", "budgetProfile",
            "promptRawUserFieldCount", "promptFinalUserFieldCount", "promptUserFieldDiffCount",
            "promptUserFieldLossCount", "promptUserFieldChangedCount", "promptUserFieldAddedCount",
            "promptUserFieldCompactedMarkerCount", "promptUserFieldTruncatedMarkerCount",
            "promptUserFieldLineageSummary",
            "promptSourceContextLedgerStoragePolicy", "promptFieldStateLedgerStoragePolicy",
            "promptRawUserFieldLedgerStoragePolicy", "promptFinalUserFieldLedgerStoragePolicy",
            "promptUserFieldDiffLedgerStoragePolicy", "promptSourceContextLedgerOmittedCount",
            "promptFieldStateLedgerOmittedCount", "promptRawUserFieldLedgerOmittedCount",
            "promptFinalUserFieldLedgerOmittedCount", "promptUserFieldDiffLedgerOmittedCount");

    private final ObjectMapper objectMapper;

    public OfficialPromptExecutionMetadataReader(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }

    public Map<String, Object> read(String json) {
        if (!StringUtils.hasText(json)) {
            return Map.of();
        }
        Map<String, Object> result = new LinkedHashMap<>();
        try (JsonParser parser = objectMapper.getFactory().createParser(json)) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                return Map.of();
            }
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                readField(parser, result);
            }
            return Collections.unmodifiableMap(result);
        }
        catch (Exception ignored) {
            return Map.of();
        }
    }

    public String writeJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value == null ? Map.of() : value);
        }
        catch (Exception ignored) {
            return "{}";
        }
    }

    private void readField(JsonParser parser, Map<String, Object> result) throws IOException {
        if (parser.currentToken() != JsonToken.FIELD_NAME) {
            parser.skipChildren();
            return;
        }
        String key = parser.currentName();
        JsonToken token = parser.nextToken();
        if (!SELECTED_KEYS.contains(key)) {
            parser.skipChildren();
            return;
        }
        if (token == JsonToken.VALUE_STRING) {
            result.put(key, parser.getValueAsString());
        }
        else if (token == JsonToken.VALUE_NUMBER_INT || token == JsonToken.VALUE_NUMBER_FLOAT) {
            result.put(key, parser.getNumberValue());
        }
        else if (token == JsonToken.VALUE_TRUE || token == JsonToken.VALUE_FALSE) {
            result.put(key, parser.getBooleanValue());
        }
        else if (token == JsonToken.VALUE_NULL) {
            result.put(key, null);
        }
        else {
            result.put(key, objectMapper.readValue(parser, Object.class));
        }
    }
}