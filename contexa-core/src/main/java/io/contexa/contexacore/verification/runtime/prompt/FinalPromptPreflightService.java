package io.contexa.contexacore.verification.runtime.prompt;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.runtime.OfficialVerificationMessageResolver;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

public class FinalPromptPreflightService {

    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

    private final ObjectMapper objectMapper;
    private final OfficialVerificationMessageResolver messageResolver;

    public FinalPromptPreflightService(ObjectMapper objectMapper) {
        this(objectMapper, OfficialVerificationMessageResolver.classpath(Locale.KOREAN));
    }

    public FinalPromptPreflightService(
            ObjectMapper objectMapper,
            OfficialVerificationMessageResolver messageResolver) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
        this.messageResolver = Objects.requireNonNull(messageResolver, "messageResolver");
    }

    public FinalPromptPreflightResult verify(SealedEvidencePackage evidencePackage) {
        List<String> violations = new ArrayList<>();
        if (evidencePackage == null) {
            return new FinalPromptPreflightResult(false, null, List.of(message(
                    "enterprise.pqa.runtimeVerification.preflight.evidencePackageMissing")));
        }
        String userPrompt = evidencePackage.getUserPromptText();
        String computedUserPromptHash = sha256Prefixed(userPrompt);
        requireText(userPrompt, "final userPrompt", violations);
        requireText(evidencePackage.getSystemPromptText(), "final systemPrompt", violations);
        requireText(evidencePackage.getRawUserPrompt(), "raw userPrompt", violations);
        requireText(evidencePackage.getRawSystemPrompt(), "raw systemPrompt", violations);
        compareHash("userPromptHash", evidencePackage.getUserPromptHash(), computedUserPromptHash, violations);
        compareHash("systemPromptHash", evidencePackage.getSystemPromptHash(), sha256Prefixed(evidencePackage.getSystemPromptText()), violations);
        compareHash("rawUserPromptHash", evidencePackage.getRawUserPromptHash(), sha256Prefixed(evidencePackage.getRawUserPrompt()), violations);
        compareHash("rawSystemPromptHash", evidencePackage.getRawSystemPromptHash(), sha256Prefixed(evidencePackage.getRawSystemPrompt()), violations);

        Map<String, Object> promptMetadata = parseJson(
                evidencePackage.getPromptExecutionMetadataJson(), violations);
        compareOptionalMetadataHash(promptMetadata, computedUserPromptHash, violations,
                "userPromptHash", "llmUserPromptHash", "finalUserPromptHash");
        if (!StringUtils.hasText(evidencePackage.getPromptEvidenceManifestJson())) {
            violations.add(message("enterprise.pqa.runtimeVerification.preflight.manifestMissing"));
        }
        return new FinalPromptPreflightResult(violations.isEmpty(), computedUserPromptHash, violations);
    }

    public void assertReady(SealedEvidencePackage evidencePackage) {
        FinalPromptPreflightResult result = verify(evidencePackage);
        if (!result.ready()) {
            throw new FinalPromptPreflightException(result, message(
                    "enterprise.pqa.runtimeVerification.preflight.failed",
                    String.join(" ", result.violations())));
        }
    }

    private void requireText(String value, String fieldName, List<String> violations) {
        if (!StringUtils.hasText(value)) {
            violations.add(message(
                    "enterprise.pqa.runtimeVerification.preflight.promptTextMissing", fieldName));
        }
    }

    private void compareHash(String label, String storedHash, String computedHash, List<String> violations) {
        if (!StringUtils.hasText(computedHash)) {
            return;
        }
        if (!StringUtils.hasText(storedHash)) {
            violations.add(message(
                    "enterprise.pqa.runtimeVerification.preflight.hashMissing", label));
            return;
        }
        if (!normalizeHash(storedHash).equals(normalizeHash(computedHash))) {
            violations.add(message(
                    "enterprise.pqa.runtimeVerification.preflight.hashMismatch", label));
        }
    }

    private void compareOptionalMetadataHash(
            Map<String, Object> metadata,
            String computedHash,
            List<String> violations,
            String... keys) {
        if (metadata == null || metadata.isEmpty() || !StringUtils.hasText(computedHash) || keys == null) {
            return;
        }
        for (String key : keys) {
            Object raw = metadata.get(key);
            if (raw == null || !StringUtils.hasText(String.valueOf(raw))) {
                continue;
            }
            if (!normalizeHash(String.valueOf(raw)).equals(normalizeHash(computedHash))) {
                violations.add(message(
                        "enterprise.pqa.runtimeVerification.preflight.metadataHashMismatch", key));
            }
        }
    }

    private Map<String, Object> parseJson(String json, List<String> violations) {
        if (!StringUtils.hasText(json)) {
            return Map.of();
        }
        try {
            Map<String, Object> parsed = objectMapper.readValue(json, MAP_TYPE);
            return parsed == null ? Map.of() : new LinkedHashMap<>(parsed);
        }
        catch (Exception exception) {
            violations.add(message(
                    "enterprise.pqa.runtimeVerification.preflight.metadataJsonInvalid"));
            return Map.of();
        }
    }

    private String normalizeHash(String value) {
        if (value == null) {
            return "";
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return normalized.startsWith("sha256:") ? normalized : "sha256:" + normalized;
    }

    private String sha256Prefixed(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return "sha256:" + HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 digest is not available.", exception);
        }
    }

    private String message(String key, Object... args) {
        return messageResolver.resolve(key, args);
    }

    public static final class FinalPromptPreflightException extends IllegalStateException {

        private final FinalPromptPreflightResult result;

        private FinalPromptPreflightException(FinalPromptPreflightResult result, String message) {
            super(message);
            this.result = Objects.requireNonNull(result, "result");
        }

        public FinalPromptPreflightResult result() {
            return result;
        }
    }
}
