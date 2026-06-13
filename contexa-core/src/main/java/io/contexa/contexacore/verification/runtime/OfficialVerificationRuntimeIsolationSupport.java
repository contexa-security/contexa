package io.contexa.contexacore.verification.runtime;

import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class OfficialVerificationRuntimeIsolationSupport {

    private static final int SUBJECT_OPERATOR_SEGMENT_LIMIT = 24;
    private static final int SUBJECT_REQUEST_SEGMENT_LIMIT = 48;
    private static final int SESSION_SEGMENT_LIMIT = 64;
    private static final int HASH_LENGTH = 12;

    private OfficialVerificationRuntimeIsolationSupport() {
    }

    public static String verificationSubjectId(String operatorUserId, String requestId) {
        String normalizedOperator = sanitize(operatorUserId, "anonymous");
        String normalizedRequestId = sanitize(requestId, "request");
        return "official-verification:"
                + compact(normalizedOperator, SUBJECT_OPERATOR_SEGMENT_LIMIT)
                + ":"
                + compact(normalizedRequestId, SUBJECT_REQUEST_SEGMENT_LIMIT);
    }

    public static String verificationSessionId(String requestId) {
        return "official-verification-session:" + compact(sanitize(requestId, "request"), SESSION_SEGMENT_LIMIT);
    }

    private static String sanitize(String value, String fallback) {
        String normalized = StringUtils.hasText(value) ? value.trim() : fallback;
        normalized = normalized.replaceAll("[^A-Za-z0-9._:-]", "-");
        return normalized.isBlank() ? fallback : normalized;
    }

    private static String compact(String value, int maxLength) {
        if (value.length() <= maxLength) {
            return value;
        }
        String hash = shortHash(value);
        int prefixLength = Math.max(8, maxLength - HASH_LENGTH - 1);
        return value.substring(0, Math.min(prefixLength, value.length())) + "-" + hash;
    }

    private static String shortHash(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(HASH_LENGTH * 2);
            for (byte item : bytes) {
                builder.append(String.format("%02x", item));
                if (builder.length() >= HASH_LENGTH) {
                    return builder.substring(0, HASH_LENGTH);
                }
            }
            return builder.substring(0, Math.min(builder.length(), HASH_LENGTH));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 must be available for official verification runtime identifiers.", exception);
        }
    }
}
