package io.contexa.contexacore.verification.runtime.prompt;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
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

public class FinalPromptPreflightService {

    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

    private final ObjectMapper objectMapper;

    public FinalPromptPreflightService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public FinalPromptPreflightResult verify(SealedEvidencePackage evidencePackage) {
        List<String> violations = new ArrayList<>();
        if (evidencePackage == null) {
            return new FinalPromptPreflightResult(false, null, List.of("봉인 증거 패키지가 없습니다."));
        }
        String userPrompt = evidencePackage.getUserPromptText();
        String computedUserPromptHash = sha256Prefixed(userPrompt);
        requireText(userPrompt, "final userPrompt 원문이 없습니다.", violations);
        requireText(evidencePackage.getSystemPromptText(), "final systemPrompt 원문이 없습니다.", violations);
        requireText(evidencePackage.getRawUserPrompt(), "raw userPrompt 원문이 없습니다.", violations);
        requireText(evidencePackage.getRawSystemPrompt(), "raw systemPrompt 원문이 없습니다.", violations);
        compareHash("userPromptHash", evidencePackage.getUserPromptHash(), computedUserPromptHash, violations);
        compareHash("systemPromptHash", evidencePackage.getSystemPromptHash(), sha256Prefixed(evidencePackage.getSystemPromptText()), violations);
        compareHash("rawUserPromptHash", evidencePackage.getRawUserPromptHash(), sha256Prefixed(evidencePackage.getRawUserPrompt()), violations);
        compareHash("rawSystemPromptHash", evidencePackage.getRawSystemPromptHash(), sha256Prefixed(evidencePackage.getRawSystemPrompt()), violations);

        Map<String, Object> promptMetadata = parseJson(evidencePackage.getPromptExecutionMetadataJson());
        compareOptionalMetadataHash(promptMetadata, computedUserPromptHash, violations,
                "userPromptHash", "llmUserPromptHash", "finalUserPromptHash");
        if (!StringUtils.hasText(evidencePackage.getPromptEvidenceManifestJson())) {
            violations.add("실제 프롬프트 증거 manifest가 없습니다.");
        }
        return new FinalPromptPreflightResult(violations.isEmpty(), computedUserPromptHash, violations);
    }

    public void assertReady(SealedEvidencePackage evidencePackage) {
        FinalPromptPreflightResult result = verify(evidencePackage);
        if (!result.ready()) {
            throw new IllegalStateException("공식검사 실행 전제 조건 실패: PREFLIGHT_FINAL_PROMPT_CONTRACT failed: "
                    + String.join(" ", result.violations()));
        }
    }

    private void requireText(String value, String message, List<String> violations) {
        if (!StringUtils.hasText(value)) {
            violations.add(message);
        }
    }

    private void compareHash(String label, String storedHash, String computedHash, List<String> violations) {
        if (!StringUtils.hasText(computedHash)) {
            return;
        }
        if (!StringUtils.hasText(storedHash)) {
            violations.add(label + "가 없습니다.");
            return;
        }
        if (!normalizeHash(storedHash).equals(normalizeHash(computedHash))) {
            violations.add(label + "가 실제 프롬프트 원문 hash와 일치하지 않습니다.");
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
                violations.add("promptExecutionMetadata." + key + "가 final userPrompt hash와 일치하지 않습니다.");
            }
        }
    }

    private Map<String, Object> parseJson(String json) {
        if (!StringUtils.hasText(json) || objectMapper == null) {
            return Map.of();
        }
        try {
            Map<String, Object> parsed = objectMapper.readValue(json, MAP_TYPE);
            return parsed == null ? Map.of() : new LinkedHashMap<>(parsed);
        }
        catch (Exception exception) {
            throw new IllegalStateException("promptExecutionMetadata JSON을 파싱할 수 없습니다.", exception);
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
}
