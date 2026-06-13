package io.contexa.contexacore.verification.runtime.sealed;

public interface OfficialSealedEvidenceVerificationRuntime {

    OfficialSealedEvidenceVerificationResult executeAll(OfficialSealedEvidenceVerificationRequest request);

    OfficialSealedEvidenceVerificationResult findByPackageId(String packageId);
}
