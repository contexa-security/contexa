package io.contexa.contexacore.verification.evidence;

/**
 * Which assembled packages are sealed (R4-S6). The capture handler asks after it assembled a package and before it
 * stores it; a package left out is not stored, and the decision itself is never affected.
 */
@FunctionalInterface
public interface SealedEvidenceCaptureSampling {

    /** Every package is sealed. */
    SealedEvidenceCaptureSampling ALL = evidencePackage -> true;

    boolean shouldSeal(SealedEvidencePackage evidencePackage);

    /**
     * Whether the package is sealed, with what the capture knows of its decision (the action it ended in and the
     * signs of a risky allow); null when the capture could not read them. A sampling that does not weigh the decision
     * answers as it does for the package alone.
     */
    default boolean shouldSeal(SealedEvidencePackage evidencePackage, SealedCaptureDecision decision) {
        return shouldSeal(evidencePackage);
    }
}
