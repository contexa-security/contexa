package io.contexa.contexacommon.mcp.approval;

import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.stream.Collectors;

public final class AiNativeExecutionContinuityFingerprint {

    private AiNativeExecutionContinuityFingerprint() {
    }

    public static String fingerprint(
            String tenantId,
            String userId,
            String actorType,
            String executionMode,
            String requestId,
            String executionId,
            String delegationId,
            String taskPurpose,
            Collection<String> approvedScopes,
            String actionApprovalCategory) {
        String canonical = String.join("|",
                canonicalize(tenantId),
                canonicalize(userId),
                canonicalize(actorType),
                canonicalize(executionMode),
                canonicalize(requestId),
                canonicalize(executionId),
                canonicalize(delegationId),
                canonicalize(taskPurpose),
                canonicalizeScopes(approvedScopes),
                canonicalize(actionApprovalCategory));
        return sha256(canonical);
    }

    private static String canonicalize(String value) {
        return StringUtils.hasText(value) ? value.trim().toLowerCase(Locale.ROOT) : "";
    }

    private static String canonicalizeScopes(Collection<String> scopes) {
        if (scopes == null || scopes.isEmpty()) {
            return "";
        }
        return scopes.stream()
                .filter(StringUtils::hasText)
                .map(value -> value.trim().toLowerCase(Locale.ROOT))
                .collect(Collectors.toCollection(LinkedHashSet::new))
                .stream()
                .sorted()
                .collect(Collectors.joining(","));
    }

    private static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder();
            for (byte current : bytes) {
                builder.append(String.format("%02x", current));
            }
            return builder.toString();
        }
        catch (Exception e) {
            throw new IllegalStateException("Failed to compute execution continuity fingerprint", e);
        }
    }
}