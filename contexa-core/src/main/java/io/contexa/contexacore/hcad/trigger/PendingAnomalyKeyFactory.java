package io.contexa.contexacore.hcad.trigger;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;

public final class PendingAnomalyKeyFactory {

    private static final HexFormat HEX_FORMAT = HexFormat.of();

    private PendingAnomalyKeyFactory() {
    }

    public static String buildBaseKey(String userId, String contextBindingHash, String httpMethod, String requestPath) {
        return hash(String.join("|",
                normalize(userId),
                normalize(contextBindingHash),
                normalize(httpMethod),
                normalize(requestPath)));
    }

    public static String buildTriggerKey(
            String userId,
            String contextBindingHash,
            String httpMethod,
            String requestPath,
            String stateSignature) {
        return hash(String.join("|",
                normalize(userId),
                normalize(contextBindingHash),
                normalize(httpMethod),
                normalize(requestPath),
                normalize(stateSignature)));
    }
    public static String buildRiskSignature(String httpMethod, String requestPath, List<String> reasonCodes) {
        return hash(String.join("|",
                normalize(httpMethod),
                normalize(requestPath),
                String.join(",", reasonCodes == null ? List.of() : reasonCodes)));
    }

    public static String buildDedupKey(String userId, String contextBindingHash, String riskSignature) {
        return hash(String.join("|",
                normalize(userId),
                normalize(contextBindingHash),
                normalize(riskSignature)));
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim();
    }

    private static String hash(String rawValue) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawValue.getBytes(StandardCharsets.UTF_8));
            return HEX_FORMAT.formatHex(hash).substring(0, 32);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required for trigger key generation", e);
        }
    }
}
