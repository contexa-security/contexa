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
}
