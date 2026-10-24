package io.contexa.contexacore.verification.evidence;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.temporal.ChronoUnit;
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

    /** docs/agent A5-6: the schema whose hash covers the tenant, the user, the capture time and the previous package. */
    public static final int LINKED_SCHEMA_VERSION = 3;

    private final EvidenceSigner signer;

    public SealedEvidencePackageIntegrity() {
        this(null);
    }

    /** @param signer the signer of schema 3 packages; null computes and checks the hash alone */
    public SealedEvidencePackageIntegrity(EvidenceSigner signer) {
        this.signer = signer;
    }

    /** docs/agent A5-6: whether this integrity signs, so that a package may be sealed under schema 3. */
    public boolean signs() {
        return signer != null;
    }

    /**
     * docs/agent A5-6: seals a schema 3 package after the one sealed before it: its hash then covers that package's
     * hash, and the signer signs it. A package of an earlier schema keeps its hash.
     */
    public void seal(SealedEvidencePackage pkg, String previousPackageHash) {
        if (pkg.getSchemaVersion() < LINKED_SCHEMA_VERSION) {
            return;
        }
        pkg.setPreviousPackageHash(previousPackageHash);
        // docs/agent CF-28: sealed with the capture time a store keeps (to the microsecond, PostgreSQL), so the package
        // verifies when it is read back, as a decision record's time is (DecisionRecordSeal).
        if (pkg.getCapturedAt() != null) {
            pkg.setCapturedAt(pkg.getCapturedAt().truncatedTo(ChronoUnit.MICROS));
        }
        pkg.setPackageHash(computeHash(pkg));
        if (signer != null) {
            pkg.setSignatureKeyId(signer.activeKeyId());
            pkg.setPackageSignature(signer.sign(pkg.getPackageHash()));
        }
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
        if (!pkg.getPackageHash().equals(recomputed)) {
            return Status.MISMATCH;
        }
        return pkg.getSchemaVersion() < LINKED_SCHEMA_VERSION ? Status.VERIFIED : signatureStatus(pkg);
    }

    /**
     * docs/agent A5-6: a schema 3 package verifies only with a valid signature: a changed package whose hash was
     * computed again fails it. A package signed with a key this signer does not hold cannot be verified.
     */
    private Status signatureStatus(SealedEvidencePackage pkg) {
        if (signer == null || isBlank(pkg.getPackageSignature()) || isBlank(pkg.getSignatureKeyId())) {
            return Status.UNVERIFIABLE;
        }
        Boolean valid = signer.verify(pkg.getSignatureKeyId(), pkg.getPackageHash(), pkg.getPackageSignature());
        if (valid == null) {
            return Status.UNVERIFIABLE;
        }
        return valid ? Status.VERIFIED : Status.MISMATCH;
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
        if (pkg.getSchemaVersion() >= LINKED_SCHEMA_VERSION) {
            // docs/agent A5-6: whose package it is, when it was captured and what came before it.
            sb.append('|').append(safe(pkg.getTenantId()));
            sb.append('|').append(safe(pkg.getUserId()));
            sb.append('|').append(pkg.getCapturedAt() != null ? pkg.getCapturedAt().toString() : "");
            sb.append('|').append(safe(pkg.getPreviousPackageHash()));
        }
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
