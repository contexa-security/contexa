package io.contexa.contexacore.verification.runtime.prompt;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public record FinalPromptEvidenceContext(
        String packageId,
        String correlationId,
        String systemPrompt,
        String rawSystemPrompt,
        String rawUserPrompt,
        String promptHash,
        String systemPromptHash,
        String userPromptHash,
        String rawSystemPromptHash,
        String rawUserPromptHash,
        String promptEvidenceManifestJson,
        Map<String, Object> ragResults,
        FinalPromptPreflightResult preflight
) {

    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

    public FinalPromptEvidenceContext {
        Map<String, Object> safeRagResults = new LinkedHashMap<>();
        if (ragResults != null) {
            ragResults.forEach((key, value) -> {
                if (key != null) {
                    safeRagResults.put(key, value);
                }
            });
        }
        ragResults = Collections.unmodifiableMap(safeRagResults);
    }

    public static FinalPromptEvidenceContext from(
            SealedEvidencePackage evidencePackage,
            FinalPromptPreflightResult preflight,
            ObjectMapper objectMapper) {
        if (evidencePackage == null) {
            return new FinalPromptEvidenceContext(
                    null, null, null, null, null, null, null, null, null, null, null, Map.of(), preflight);
        }
        return new FinalPromptEvidenceContext(
                evidencePackage.getPackageId(),
                evidencePackage.getCorrelationId(),
                evidencePackage.getSystemPromptText(),
                evidencePackage.getRawSystemPrompt(),
                evidencePackage.getRawUserPrompt(),
                evidencePackage.getPromptHash(),
                evidencePackage.getSystemPromptHash(),
                evidencePackage.getUserPromptHash(),
                evidencePackage.getRawSystemPromptHash(),
                evidencePackage.getRawUserPromptHash(),
                evidencePackage.getPromptEvidenceManifestJson(),
                parseJson(evidencePackage.getRagResultsJson(), objectMapper),
                preflight);
    }

    private static Map<String, Object> parseJson(String json, ObjectMapper objectMapper) {
        if (!StringUtils.hasText(json)) {
            return Map.of();
        }
        try {
            ObjectMapper mapper = Objects.requireNonNull(objectMapper, "objectMapper");
            Map<String, Object> parsed = mapper.readValue(json, MAP_TYPE);
            return parsed == null ? Map.of() : new LinkedHashMap<>(parsed);
        }
        catch (Exception exception) {
            Map<String, Object> failed = new LinkedHashMap<>();
            failed.put("ragSearchExecuted", true);
            failed.put("providerError", true);
            failed.put("ragParseError", true);
            failed.put("status", "PROVIDER_ERROR");
            failed.put("retrievalStatus", "PROVIDER_ERROR");
            failed.put("ragRetrievalState", "PROVIDER_ERROR");
            failed.put("ragAbsenceReason", "Malformed RAG evidence JSON could not be parsed.");
            failed.put("ragParseErrorType", exception.getClass().getSimpleName());
            return failed;
        }
    }
}
