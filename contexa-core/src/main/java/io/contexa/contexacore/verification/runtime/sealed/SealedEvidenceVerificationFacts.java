package io.contexa.contexacore.verification.runtime.sealed;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.metric.OfficialContextHashStateResolver;
import io.contexa.contexacore.verification.runtime.OfficialVerificationMessageResolver;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

/** Extracts normalized verification facts from a sealed evidence package. */
final class SealedEvidenceVerificationFacts {

    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};
    private static final String[] PROMPT_METADATA_FACT_KEYS = {
            "promptVersion",
            "contractVersion",
            "templateKey",
            "templateName",
            "promptHash",
            "contextHash",
            "canonicalContextHash",
            "estimatedInputTokens",
            "estimatedOutputTokens",
            "actualPromptTokens",
            "budgetProfile",
            "budgetViewProfile",
            "promptTransformationMode",
            "promptBudgetExceeded",
            "promptBudgetRemainingTokens",
            "rawUserPromptLength",
            "llmUserPromptLength",
            "runtimeProvider",
            "runtimeModelId",
            "runtimeTemperature",
            "runtimeTopP",
            "runtimeSeed"
    };

    private SealedEvidenceVerificationFacts() {
    }

    static Map<String, String> promptFacts(
            ObjectMapper objectMapper,
            SealedEvidencePackage evidencePackage,
            Map<String, Object> promptMetadata,
            OfficialVerificationMessageResolver messageResolver) {
        Map<String, String> facts = new LinkedHashMap<>();
        copyPromptMetadataFacts(facts, promptMetadata);
        Map<String, Object> requestFacts = parseJson(objectMapper, evidencePackage.getRequestFactsJson());
        OfficialContextHashStateResolver.Resolution contextHashResolution =
                OfficialContextHashStateResolver.resolve(
                        requestFacts, promptMetadata, evidencePackage.getCanonicalContextJson(), messageResolver);
        putIfPresent(facts, "promptHash", firstNonBlank(evidencePackage.getPromptHash(), facts.get("promptHash")));
        putIfPresent(facts, "contextHash", contextHashResolution.contextHash());
        putIfPresent(facts, "contextHashState", contextHashResolution.state());
        putIfPresent(facts, "contextHashStateReason", contextHashResolution.reason());
        facts.put("rawSystemPromptCaptured", String.valueOf(StringUtils.hasText(evidencePackage.getRawSystemPrompt())));
        facts.put("rawUserPromptCaptured", String.valueOf(StringUtils.hasText(evidencePackage.getRawUserPrompt())));
        facts.put("llmSystemPromptCaptured", String.valueOf(StringUtils.hasText(evidencePackage.getSystemPromptText())));
        facts.put("llmUserPromptCaptured", String.valueOf(StringUtils.hasText(evidencePackage.getUserPromptText())));
        facts.put("baselineSnapshotCaptured", String.valueOf(StringUtils.hasText(evidencePackage.getBaselineSnapshotJson())));
        facts.put("ragResultsCaptured", String.valueOf(StringUtils.hasText(evidencePackage.getRagResultsJson())));
        putIfPresent(facts, "rawSystemPromptHash", prefixedSha256(evidencePackage.getRawSystemPrompt()));
        putIfPresent(facts, "rawUserPromptHash", prefixedSha256(evidencePackage.getRawUserPrompt()));
        putIfPresent(facts, "systemPromptHash", prefixedSha256(evidencePackage.getSystemPromptText()));
        putIfPresent(facts, "userPromptHash", prefixedSha256(evidencePackage.getUserPromptText()));
        putIfPresent(facts, "rawSystemPromptRef", promptRef(evidencePackage, "raw_system_prompt"));
        putIfPresent(facts, "rawUserPromptRef", promptRef(evidencePackage, "raw_user_prompt"));
        putIfPresent(facts, "systemPromptTextRef", promptRef(evidencePackage, "system_prompt_text"));
        putIfPresent(facts, "userPromptTextRef", promptRef(evidencePackage, "user_prompt_text"));
        putIfPresent(facts, "promptExecutionMetadataRef", promptRef(evidencePackage, "prompt_execution_metadata_json"));
        putIfPresent(facts, "promptEvidenceManifestRef", promptRef(evidencePackage, "prompt_evidence_manifest_json"));
        putIfPresent(facts, "promptFieldStateLedgerRef",
                promptRef(evidencePackage, "prompt_evidence_manifest_json") + ":fieldStateLedger");
        putIfPresent(facts, "promptSourceContextLedgerRef",
                promptRef(evidencePackage, "prompt_execution_metadata_json") + ":promptSourceContextLedgerStoragePolicy");
        putIfPresent(facts, "promptRawUserFieldLedgerRef",
                promptRef(evidencePackage, "prompt_execution_metadata_json") + ":promptRawUserFieldLedgerStoragePolicy");
        putIfPresent(facts, "promptFinalUserFieldLedgerRef",
                promptRef(evidencePackage, "prompt_execution_metadata_json") + ":promptFinalUserFieldLedgerStoragePolicy");
        return facts;
    }

    static Map<String, String> requestAndAuthFacts(
            Map<String, Object> requestFacts,
            Map<String, Object> authState,
            Map<String, Object> decision) {
        Map<String, String> facts = new LinkedHashMap<>(stringMap(requestFacts));
        putIfPresent(facts, "requestPath", firstNonBlank(
                facts.get("requestPath"),
                facts.get("resourceUrl"),
                facts.get("path"),
                facts.get("uri")));
        putIfPresent(facts, "httpMethod", firstNonBlank(facts.get("httpMethod"), facts.get("method")));
        putIfPresent(facts, "resourceId", firstNonBlank(facts.get("resourceId"), facts.get("endpointKey")));
        putIfPresent(facts, "clientIp", firstNonBlank(facts.get("clientIp"), facts.get("ipAddress"), facts.get("remoteAddr")));
        Map<String, String> authFacts = stringMap(authState);
        putIfPresent(facts, "mfaVerified", authFacts.get("mfaVerified"));
        putIfPresent(facts, "authMethod", firstNonBlank(authFacts.get("authMethod"), authFacts.get("authenticationMethod")));
        putIfPresent(facts, "authorizationEffect", authFacts.get("authorizationEffect"));
        putIfPresent(facts, "effectiveRoles", firstNonBlank(authFacts.get("effectiveRoles"), authFacts.get("roles")));
        putIfPresent(facts, "effectivePermissions", firstNonBlank(authFacts.get("effectivePermissions"), authFacts.get("permissions")));
        Map<String, String> decisionFacts = stringMap(decision);
        putIfPresent(facts, "decisionAction", firstNonBlank(
                decisionFacts.get("action"),
                decisionFacts.get("decisionAction"),
                decisionFacts.get("effect")));
        return Map.copyOf(facts);
    }

    static Map<String, Object> parseJson(ObjectMapper objectMapper, String json) {
        if (!StringUtils.hasText(json)) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, MAP_TYPE);
        }
        catch (Exception ignored) {
            return Map.of();
        }
    }

    private static Map<String, String> stringMap(Map<String, Object> raw) {
        if (raw == null || raw.isEmpty()) {
            return Map.of();
        }
        Map<String, String> result = new LinkedHashMap<>();
        raw.forEach((key, value) -> putIfPresent(result, key, value == null ? null : String.valueOf(value)));
        return result;
    }

    private static void copyPromptMetadataFacts(Map<String, String> facts, Map<String, Object> promptMetadata) {
        if (promptMetadata == null || promptMetadata.isEmpty()) {
            return;
        }
        for (String key : PROMPT_METADATA_FACT_KEYS) {
            Object value = promptMetadata.get(key);
            if (value instanceof Map<?, ?> || value instanceof Iterable<?> || (value != null && value.getClass().isArray())) {
                continue;
            }
            putIfPresent(facts, key, value == null ? null : String.valueOf(value));
        }
    }

    static String text(Map<String, Object> raw, String key) {
        Object value = raw == null ? null : raw.get(key);
        return value == null ? null : String.valueOf(value);
    }

    static void putIfPresent(Map<String, String> target, String key, String value) {
        if (StringUtils.hasText(value)) {
            target.put(key, value.trim());
        }
    }

    static String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    static String sha256(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 digest is not available.", exception);
        }
    }

    private static String prefixedSha256(String value) {
        String digest = sha256(value);
        return digest == null ? null : "sha256:" + digest;
    }

    private static String promptRef(SealedEvidencePackage evidencePackage, String columnName) {
        if (evidencePackage == null || !StringUtils.hasText(evidencePackage.getPackageId())) {
            return null;
        }
        return "sealed_evidence_package." + columnName + "#" + evidencePackage.getPackageId();
    }
}