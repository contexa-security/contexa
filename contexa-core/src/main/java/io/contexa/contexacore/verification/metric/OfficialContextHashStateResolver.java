package io.contexa.contexacore.verification.metric;

import io.contexa.contexacore.verification.runtime.OfficialVerificationMessageResolver;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;

public final class OfficialContextHashStateResolver {

    public static final String PRESENT = "PRESENT";
    public static final String COMPUTED_FROM_CANONICAL_CONTEXT = "COMPUTED_FROM_CANONICAL_CONTEXT";
    public static final String MISSING_CANONICAL_CONTEXT = "MISSING_CANONICAL_CONTEXT";
    public static final String METADATA_MISMATCH = "METADATA_MISMATCH";

    private OfficialContextHashStateResolver() {
    }

    public static Resolution resolve(
            Map<String, Object> requestFacts,
            Map<String, Object> promptMetadata,
            String canonicalContextJson) {
        return resolve(
                requestFacts,
                promptMetadata,
                canonicalContextJson,
                OfficialVerificationMessageResolver.classpath(Locale.KOREAN));
    }

    public static Resolution resolve(
            Map<String, Object> requestFacts,
            Map<String, Object> promptMetadata,
            String canonicalContextJson,
            OfficialVerificationMessageResolver messageResolver) {
        String metadataHash = firstNonBlank(
                text(promptMetadata, "contextHash"),
                text(promptMetadata, "canonicalContextHash"));
        String requestHash = firstNonBlank(
                text(requestFacts, "contextHash"),
                text(requestFacts, "canonicalContextHash"));
        String declaredState = firstNonBlank(
                text(promptMetadata, "contextHashState"),
                text(promptMetadata, "contextHashStatus"),
                text(requestFacts, "contextHashState"),
                text(requestFacts, "contextHashStatus"));
        String computedHash = sha256(canonicalContextJson);

        if (isMismatchState(declaredState)) {
            return new Resolution(firstNonBlank(metadataHash, requestHash, computedHash), METADATA_MISMATCH,
                    messageResolver.resolve(
                            "enterprise.pqa.runtimeVerification.contextHash.declaredMismatch"));
        }
        if (StringUtils.hasText(metadataHash) && StringUtils.hasText(requestHash)
                && !metadataHash.trim().equals(requestHash.trim())) {
            return new Resolution(firstNonBlank(metadataHash, requestHash), METADATA_MISMATCH,
                    messageResolver.resolve(
                            "enterprise.pqa.runtimeVerification.contextHash.sourceMismatch"));
        }
        String explicitHash = firstNonBlank(metadataHash, requestHash);
        if (StringUtils.hasText(explicitHash) && StringUtils.hasText(computedHash)
                && !normalizeHash(explicitHash).equals(normalizeHash(computedHash))) {
            return new Resolution(explicitHash, METADATA_MISMATCH,
                    messageResolver.resolve(
                            "enterprise.pqa.runtimeVerification.contextHash.recalculationMismatch"));
        }
        if (StringUtils.hasText(explicitHash)) {
            return new Resolution(explicitHash, PRESENT,
                    messageResolver.resolve(
                            "enterprise.pqa.runtimeVerification.contextHash.explicit"));
        }
        if (StringUtils.hasText(computedHash)) {
            return new Resolution(computedHash, COMPUTED_FROM_CANONICAL_CONTEXT,
                    messageResolver.resolve(
                            "enterprise.pqa.runtimeVerification.contextHash.computed"));
        }
        return new Resolution("", MISSING_CANONICAL_CONTEXT,
                messageResolver.resolve(
                        "enterprise.pqa.runtimeVerification.contextHash.missing"));
    }

    public static boolean isAcceptableForOfficialInspection(String state) {
        String normalized = normalizeState(state);
        return PRESENT.equals(normalized) || COMPUTED_FROM_CANONICAL_CONTEXT.equals(normalized);
    }

    private static String text(Map<String, Object> source, String key) {
        if (source == null || key == null) {
            return null;
        }
        Object value = source.get(key);
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

    private static boolean isMismatchState(String state) {
        return METADATA_MISMATCH.equals(normalizeState(state));
    }

    private static String normalizeState(String state) {
        return state == null ? "" : state.trim().toUpperCase(Locale.ROOT);
    }

    private static String normalizeHash(String value) {
        String normalized = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        return normalized.startsWith("sha256:") ? normalized.substring("sha256:".length()) : normalized;
    }

    private static String sha256(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 digest is not available.", exception);
        }
    }

    public record Resolution(String contextHash, String state, String reason) {
    }
}
