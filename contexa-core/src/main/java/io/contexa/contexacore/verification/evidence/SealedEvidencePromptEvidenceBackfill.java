package io.contexa.contexacore.verification.evidence;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds an official-verification-ready detached copy of a sealed evidence
 * package. This is used for legacy packages created before the prompt evidence
 * manifest columns existed. The original persisted package is not mutated.
 */
public final class SealedEvidencePromptEvidenceBackfill {

    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};
    private static final HexFormat HEX = HexFormat.of();
    private static final SealedEvidencePackageIntegrity INTEGRITY = new SealedEvidencePackageIntegrity();

    private SealedEvidencePromptEvidenceBackfill() {
    }

    public static Result prepare(ObjectMapper objectMapper, SealedEvidencePackage source) {
        if (source == null) {
            return new Result(null, List.of("봉인 증거 패키지가 없습니다."), List.of());
        }
        SealedEvidencePackage pkg = copyOf(source);
        List<String> violations = new ArrayList<>();
        List<String> recoveredFields = new ArrayList<>();

        requirePromptText(pkg.getSystemPromptText(), "systemPromptText", violations);
        requirePromptText(pkg.getUserPromptText(), "userPromptText", violations);
        requirePromptText(pkg.getRawSystemPrompt(), "rawSystemPrompt", violations);
        requirePromptText(pkg.getRawUserPrompt(), "rawUserPrompt", violations);

        recoverHash(pkg::getSystemPromptHash, pkg::setSystemPromptHash, pkg.getSystemPromptText(), "systemPromptHash", recoveredFields);
        recoverHash(pkg::getUserPromptHash, pkg::setUserPromptHash, pkg.getUserPromptText(), "userPromptHash", recoveredFields);
        recoverHash(pkg::getRawSystemPromptHash, pkg::setRawSystemPromptHash, pkg.getRawSystemPrompt(), "rawSystemPromptHash", recoveredFields);
        recoverHash(pkg::getRawUserPromptHash, pkg::setRawUserPromptHash, pkg.getRawUserPrompt(), "rawUserPromptHash", recoveredFields);

        Map<String, Object> metadata = readMap(objectMapper, pkg.getPromptExecutionMetadataJson());
        boolean metadataChanged = putIfAbsent(metadata, "systemPromptHash", pkg.getSystemPromptHash())
                | putIfAbsent(metadata, "userPromptHash", pkg.getUserPromptHash())
                | putIfAbsent(metadata, "rawSystemPromptHash", pkg.getRawSystemPromptHash())
                | putIfAbsent(metadata, "rawUserPromptHash", pkg.getRawUserPromptHash());
        if (metadataChanged) {
            pkg.setPromptExecutionMetadataJson(writeMap(objectMapper, metadata));
            recoveredFields.add("promptExecutionMetadataJson.promptHashes");
        }

        if (!StringUtils.hasText(pkg.getPromptEvidenceManifestJson())) {
            if (StringUtils.hasText(pkg.getUserPromptText())) {
                UserPromptEvidenceContract.Result contract = UserPromptEvidenceContract.evaluate(
                        objectMapper,
                        pkg.getUserPromptText(),
                        pkg.getRequestFactsJson(),
                        pkg.getAuthStateJson(),
                        pkg.getCanonicalContextJson(),
                        pkg.getBaselineSnapshotJson(),
                        pkg.getRagResultsJson(),
                        pkg.getPromptExecutionMetadataJson(),
                        pkg.getDecisionJson());
                pkg.setPromptEvidenceManifestJson(contract.manifestJson());
                recoveredFields.add("promptEvidenceManifestJson");
            }
            else {
                violations.add("실제 사용자 프롬프트 원문이 없어 증거 매니페스트를 만들 수 없습니다.");
            }
        }

        if (!"SEALED".equalsIgnoreCase(firstNonBlank(pkg.getSealState(), ""))) {
            if (!StringUtils.hasText(pkg.getSealState())) {
                pkg.setSealState("SEALED");
                recoveredFields.add("sealState");
            }
            else {
                violations.add("sealState가 SEALED가 아닙니다: " + pkg.getSealState());
            }
        }
        if (pkg.getSchemaVersion() < 2) {
            pkg.setSchemaVersion(2);
            recoveredFields.add("schemaVersion");
        }

        if (!violations.isEmpty()) {
            return new Result(pkg, List.copyOf(violations), List.copyOf(recoveredFields));
        }
        if (!recoveredFields.isEmpty()) {
            pkg.setPackageHash(INTEGRITY.computeHash(pkg));
            recoveredFields.add("packageHash");
        }
        return new Result(pkg, List.of(), List.copyOf(recoveredFields));
    }

    private static void requirePromptText(String value, String fieldName, List<String> violations) {
        if (!StringUtils.hasText(value)) {
            violations.add(fieldName + "가 없습니다.");
        }
    }

    private static void recoverHash(
            ValueReader reader,
            ValueWriter writer,
            String promptText,
            String fieldName,
            List<String> recoveredFields) {
        if (StringUtils.hasText(reader.read())) {
            return;
        }
        if (!StringUtils.hasText(promptText)) {
            return;
        }
        writer.write(sha256Prefixed(promptText));
        recoveredFields.add(fieldName);
    }

    private static boolean putIfAbsent(Map<String, Object> metadata, String key, String value) {
        if (!StringUtils.hasText(value)) {
            return false;
        }
        Object current = metadata.get(key);
        if (current instanceof String text && StringUtils.hasText(text)) {
            return false;
        }
        metadata.put(key, value);
        return true;
    }

    private static Map<String, Object> readMap(ObjectMapper objectMapper, String json) {
        if (!StringUtils.hasText(json)) {
            return new LinkedHashMap<>();
        }
        try {
            Map<String, Object> parsed = objectMapper.readValue(json, MAP_TYPE);
            return parsed == null ? new LinkedHashMap<>() : new LinkedHashMap<>(parsed);
        }
        catch (JsonProcessingException ignored) {
            return new LinkedHashMap<>();
        }
    }

    private static String writeMap(ObjectMapper objectMapper, Map<String, Object> metadata) {
        if (metadata == null || metadata.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(metadata);
        }
        catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize prompt execution metadata", e);
        }
    }

    private static String summarizeViolations(List<Map<String, Object>> violations) {
        if (violations == null || violations.isEmpty()) {
            return "상세 위반 항목 없음";
        }
        return violations.stream()
                .limit(5)
                .map(row -> firstNonBlank(
                        value(row.get("displayName")),
                        value(row.get("fieldKey")),
                        "알 수 없는 항목"))
                .distinct()
                .toList()
                .toString();
    }

    private static String value(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private static String firstNonBlank(String... values) {
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

    private static String sha256Prefixed(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return "sha256:" + HEX.formatHex(hash);
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }

    private static SealedEvidencePackage copyOf(SealedEvidencePackage source) {
        return SealedEvidencePackage.builder()
                .id(source.getId())
                .packageId(source.getPackageId())
                .correlationId(source.getCorrelationId())
                .tenantId(source.getTenantId())
                .userId(source.getUserId())
                .capturedAt(source.getCapturedAt())
                .requestFactsJson(source.getRequestFactsJson())
                .authStateJson(source.getAuthStateJson())
                .canonicalContextJson(source.getCanonicalContextJson())
                .baselineSnapshotJson(source.getBaselineSnapshotJson())
                .ragResultsJson(source.getRagResultsJson())
                .rawSystemPrompt(source.getRawSystemPrompt())
                .rawUserPrompt(source.getRawUserPrompt())
                .systemPromptText(source.getSystemPromptText())
                .userPromptText(source.getUserPromptText())
                .promptHash(source.getPromptHash())
                .systemPromptHash(source.getSystemPromptHash())
                .userPromptHash(source.getUserPromptHash())
                .rawSystemPromptHash(source.getRawSystemPromptHash())
                .rawUserPromptHash(source.getRawUserPromptHash())
                .promptExecutionMetadataJson(source.getPromptExecutionMetadataJson())
                .promptEvidenceManifestJson(source.getPromptEvidenceManifestJson())
                .sealState(source.getSealState())
                .sealFailureReason(source.getSealFailureReason())
                .decisionJson(source.getDecisionJson())
                .packageHash(source.getPackageHash())
                .schemaVersion(source.getSchemaVersion())
                .sealed(source.isSealed())
                .expiresAt(source.getExpiresAt())
                .createdAt(source.getCreatedAt())
                .build();
    }

    @FunctionalInterface
    private interface ValueReader {
        String read();
    }

    @FunctionalInterface
    private interface ValueWriter {
        void write(String value);
    }

    public record Result(
            SealedEvidencePackage packageForVerification,
            List<String> violations,
            List<String> recoveredFields) {
        public boolean ready() {
            return violations == null || violations.isEmpty();
        }

        public boolean recovered() {
            return recoveredFields != null && !recoveredFields.isEmpty();
        }
    }
}
