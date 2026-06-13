package io.contexa.contexacore.verification.evidence;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Computes and verifies SHA-256 integrity hashes for sealed evidence packages.
 * The hash covers sections 1-7 (request facts through decision) to ensure tamper evidence.
 */
public class SealedEvidencePackageIntegrity {

    private static final HexFormat HEX = HexFormat.of();

    public String computeHash(SealedEvidencePackage pkg) {
        String payload = buildHashPayload(pkg);
        return sha256(payload);
    }

    public boolean verify(SealedEvidencePackage pkg) {
        if (pkg == null || pkg.getPackageHash() == null) {
            return false;
        }
        String recomputed = computeHash(pkg);
        return pkg.getPackageHash().equals(recomputed);
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
