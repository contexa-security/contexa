package io.contexa.contexacore.verification.evidence;

import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;

/**
 * Computes and verifies SHA-256 integrity hashes for sealed evidence packages.
 * The hash covers sections 1-7 (request facts through decision) to ensure tamper evidence.
 *
 * Verification must be applied to the package exactly as it was persisted. A package whose
 * package hash is blank, or (schema version 2 and later) whose prompt hash field is blank while
 * the hashed prompt text is present, cannot be verified and is never reported as valid.
 *
 * <p>Q-21: where this integrity signs, a package that should carry a signature and has none fails, whatever its schema
 * says: one with the hash of a linked schema, and one captured after the oldest signed package kept. With a store's
 * {@link #setChain chain} a package also fails when the package it was sealed after is gone while the retention cannot
 * have taken it. So does one that names a key the installation never held, where its signer keeps its keys.</p>
 *
 * <p>What the seal cannot tell, without something kept outside the database: the last package removed, since nothing
 * names it; every package up to the last lowered together, and every package from the first up to one point lowered and
 * dated back together, which read as signing that began later; and a package removed from the part of the chain the
 * retention may already have reached.</p>
 */
@Slf4j
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

    /** Why a package has its status, for whoever reads the outcome. */
    public enum Cause {
        INTACT,
        /** The package has no hash to check, or a sealed prompt has none. */
        NOT_HASHED,
        /** A field the hash covers changed, or the signature is not the hash's. */
        CHANGED,
        /** The package should carry a signature and does not. */
        UNSIGNED,
        /** The package it was sealed after is gone, and the retention cannot have taken it. */
        LINK_BROKEN,
        /** No signer holds the key the signature names, or there is no signer. */
        KEY_NOT_HELD,
        /** The signature names a key this installation never held, on a package of the time its key signs. */
        KEY_NOT_KNOWN,
        /** The store could not say what is kept around the package. */
        STORE_NOT_READ
    }

    /** A package's status and why it has it. */
    public record Evaluation(Status status, Cause cause) {
    }

    /** docs/agent A5-6: the schema whose hash covers the tenant, the user, the capture time and the previous package. */
    public static final int LINKED_SCHEMA_VERSION = 3;

    private final EvidenceSigner signer;
    private volatile SealedEvidenceChain chain;
    private volatile Duration keptAtLeast;
    private volatile Clock clock;

    public SealedEvidencePackageIntegrity() {
        this(null);
    }

    /** @param signer the signer of schema 3 packages; null computes and checks the hash alone */
    public SealedEvidencePackageIntegrity(EvidenceSigner signer) {
        this.signer = signer;
    }

    /**
     * Q-21: reads what a store keeps around a package.
     *
     * @param chain       the store's answers
     * @param keptAtLeast how long the retention leaves every package alone: inside it a package that is gone was removed
     * @param clock       the time the retention is counted from
     */
    public void setChain(SealedEvidenceChain chain, Duration keptAtLeast, Clock clock) {
        this.keptAtLeast = keptAtLeast;
        this.clock = clock;
        this.chain = chain;
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
        return examine(pkg).status();
    }

    /** The package's status with its cause. A store that does not answer leaves the package unread: nothing stops. */
    public Evaluation examine(SealedEvidencePackage pkg) {
        if (pkg == null) {
            return new Evaluation(Status.UNVERIFIABLE, Cause.NOT_HASHED);
        }
        try {
            return examineStored(pkg);
        } catch (RuntimeException e) {
            log.error("[SealedEvidence] The packages around {} could not be read", pkg.getPackageId(), e);
            return new Evaluation(Status.UNVERIFIABLE, Cause.STORE_NOT_READ);
        }
    }

    private Evaluation examineStored(SealedEvidencePackage pkg) {
        boolean signatureDue = signatureDue(pkg);
        if (isBlank(pkg.getPackageHash()) || hasMissingPromptHash(pkg)) {
            return signatureDue ? new Evaluation(Status.MISMATCH, Cause.UNSIGNED)
                    : new Evaluation(Status.UNVERIFIABLE, Cause.NOT_HASHED);
        }
        if (!pkg.getPackageHash().equals(computeHash(pkg))) {
            return new Evaluation(Status.MISMATCH, Cause.CHANGED);
        }
        if (signatureDue && (isBlank(pkg.getPackageSignature()) || isBlank(pkg.getSignatureKeyId()))) {
            return new Evaluation(Status.MISMATCH, Cause.UNSIGNED);
        }
        if (linkBroken(pkg)) {
            return new Evaluation(Status.MISMATCH, Cause.LINK_BROKEN);
        }
        // A lowered package carrying any text as its signature is checked as well, or the schema would waive it.
        return pkg.getSchemaVersion() < LINKED_SCHEMA_VERSION && !signatureDue
                ? new Evaluation(Status.VERIFIED, Cause.INTACT) : signatureEvaluation(pkg);
    }

    /**
     * Q-21: whether this package should carry a signature: a linked schema is signed when it is sealed, and an older
     * one captured after the oldest signed package kept can only be a lowered one, since signing does not stop. The
     * time of that package is signed itself, so a package cannot be made older than it without breaking a link.
     */
    private boolean signatureDue(SealedEvidencePackage pkg) {
        if (signer == null) {
            return false;
        }
        if (pkg.getSchemaVersion() >= LINKED_SCHEMA_VERSION) {
            return true;
        }
        SealedEvidenceChain store = chain;
        if (store == null || pkg.getCapturedAt() == null) {
            return false;
        }
        return store.signedSince().filter(pkg.getCapturedAt()::isAfter).isPresent();
    }

    /**
     * Q-21: whether the package it was sealed after was removed. The retention removes the oldest packages, and clean
     * packages from inside the chain once they are older than the clean period, so a package that is gone counts only
     * when the package kept right before it is younger than the shortest retention: the one that went is younger still.
     */
    private boolean linkBroken(SealedEvidencePackage pkg) {
        SealedEvidenceChain store = chain;
        if (store == null || pkg.getId() == null || isBlank(pkg.getPreviousPackageHash()) || store.previousKept(pkg)) {
            return false;
        }
        Instant horizon = clock.instant().minus(keptAtLeast);
        return store.capturedBefore(pkg).filter(horizon::isBefore).isPresent();
    }

    /**
     * docs/agent A5-6: a schema 3 package verifies only with a valid signature: a changed package whose hash was
     * computed again fails it. A package signed with a key this signer does not hold cannot be verified, unless it was
     * never the installation's own.
     */
    private Evaluation signatureEvaluation(SealedEvidencePackage pkg) {
        if (signer == null) {
            return new Evaluation(Status.UNVERIFIABLE, Cause.KEY_NOT_HELD);
        }
        Boolean valid = signer.verify(pkg.getSignatureKeyId(), pkg.getPackageHash(), pkg.getPackageSignature());
        if (valid == null) {
            return keyNeverHeld(pkg) ? new Evaluation(Status.MISMATCH, Cause.KEY_NOT_KNOWN)
                    : new Evaluation(Status.UNVERIFIABLE, Cause.KEY_NOT_HELD);
        }
        return valid ? new Evaluation(Status.VERIFIED, Cause.INTACT) : new Evaluation(Status.MISMATCH, Cause.CHANGED);
    }

    /**
     * Whether a key the signer does not hold can only be a made-up one: the signer keeps its keys, and the package
     * dates from the time its active key signs. Before that an ephemeral key or a key taken off the list may have signed,
     * and anybody can write such a name, so the time decides and not the name. The time of the first package under the
     * active key is signed itself, so a package moved before it breaks a link instead.
     */
    private boolean keyNeverHeld(SealedEvidencePackage pkg) {
        SealedEvidenceChain store = chain;
        if (store == null || !signer.keepsItsKeys() || pkg.getCapturedAt() == null) {
            return false;
        }
        return store.signedSince(signer.activeKeyId()).filter(pkg.getCapturedAt()::isAfter).isPresent();
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
