package io.contexa.contexacore.verification.evidence;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Computes and verifies SHA-256 integrity hashes for sealed evidence packages.
 * The hash covers sections 1-7 (request facts through decision) to ensure tamper evidence.
 *
 * Verification must be applied to the package exactly as it was persisted. A package whose
 * package hash is blank, or (schema version 2 and later) whose prompt hash field is blank while
 * the hashed prompt text is present, cannot be verified and is never reported as valid.
 */
public class SealedEvidencePackageIntegrity {

    private static final HexFormat HEX = HexFormat.of();

    /**
     * Integrity outcome of a persisted sealed evidence package.
     */
    public enum Status {
        VERIFIED,
        MISMATCH,
        UNVERIFIABLE
    }

    public String computeHash(SealedEvidencePackage pkg) {
        String payload = buildHashPayload(pkg);
        return sha256(payload);
    }

    public boolean verify(SealedEvidencePackage pkg) {
        return evaluate(pkg) == Status.VERIFIED;
    }

    public Status evaluate(SealedEvidencePackage pkg) {
        if (pkg == null || isBlank(pkg.getPackageHash()) || hasMissingPromptHash(pkg)) {
            return Status.UNVERIFIABLE;
        }
        String recomputed = computeHash(pkg);
        return pkg.getPackageHash().equals(recomputed) ? Status.VERIFIED : Status.MISMATCH;
    }

    private boolean hasMissingPromptHash(SealedEvidencePackage pkg) {
        if (pkg.getSchemaVersion() < 2) {
            return false;
        }
        return missingHash(pkg.getSystemPromptText(), pkg.getSystemPromptHash())
                || missingHash(pkg.getUserPromptText(), pkg.getUserPromptHash())
                || missingHash(pkg.getRawSystemPrompt(), pkg.getRawSystemPromptHash())
                || missingHash(pkg.getRawUserPrompt(), pkg.getRawUserPromptHash());
    }

    private boolean missingHash(String text, String hash) {
        return !isBlank(text) && isBlank(hash);
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private String buildHashPayload(SealedEvidencePackage pkg) {
        StringBuilder sb = new StringBuilder();
        sb.append(safe(pkg.getPackageId()));
        sb.append('|').append(safe(pkg.getCorrelationId()));
        sb.append('|').append(safe(pkg.getRequestFactsJson()));
        sb.append('|').append(safe(pkg.getAuthStateJson()));
        sb.append('|').append(safe(pkg.getCanonicalContextJson()));
        sb.append('|').append(safe(pkg.getBaselineSnapshotJson()));
        sb.append('|').append(safe(pkg.getRagResultsJson()));
        sb.append('|').append(safe(pkg.getRawSystemPrompt()));
        sb.append('|').append(safe(pkg.getRawUserPrompt()));
        sb.append('|').append(safe(pkg.getSystemPromptText()));
        sb.append('|').append(safe(pkg.getUserPromptText()));
        if (pkg.getSchemaVersion() >= 2) {
            sb.append('|').append(safe(pkg.getSystemPromptHash()));
            sb.append('|').append(safe(pkg.getUserPromptHash()));
            sb.append('|').append(safe(pkg.getRawSystemPromptHash()));
            sb.append('|').append(safe(pkg.getRawUserPromptHash()));
            sb.append('|').append(safe(pkg.getPromptEvidenceManifestJson()));
            sb.append('|').append(safe(pkg.getSealState()));
        }
        sb.append('|').append(safe(pkg.getPromptExecutionMetadataJson()));
        sb.append('|').append(safe(pkg.getDecisionJson()));
        sb.append('|').append(pkg.getSchemaVersion());
        return sb.toString();
    }

    private String safe(String value) {
        return value != null ? value : "";
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HEX.formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}
