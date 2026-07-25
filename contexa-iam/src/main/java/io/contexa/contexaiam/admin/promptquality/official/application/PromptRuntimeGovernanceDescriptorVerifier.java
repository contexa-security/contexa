package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeGovernanceDescriptorVerificationResult;

import java.util.Map;

public interface PromptRuntimeGovernanceDescriptorVerifier {

    RuntimeGovernanceDescriptorVerificationResult verify(
            SealedEvidencePackage evidencePackage,
            Map<String, Object> promptMetadata);

    static PromptRuntimeGovernanceDescriptorVerifier none() {
        return (evidencePackage, promptMetadata) -> RuntimeGovernanceDescriptorVerificationResult.empty();
    }
}
