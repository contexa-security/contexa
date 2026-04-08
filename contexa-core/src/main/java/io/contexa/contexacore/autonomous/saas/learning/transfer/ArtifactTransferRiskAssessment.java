package io.contexa.contexacore.autonomous.saas.learning.transfer;

import java.util.List;

/**
 * Final transfer gate result for cross-tenant artifact sharing.
 */
public record ArtifactTransferRiskAssessment(
        boolean sharingEnabled,
        ArtifactTransferRiskLevel riskLevel,
        boolean quarantineRecommended,
        List<String> policyFacts) {

    public ArtifactTransferRiskAssessment {
        riskLevel = riskLevel == null ? ArtifactTransferRiskLevel.HIGH : riskLevel;
        policyFacts = policyFacts == null ? List.of() : List.copyOf(policyFacts);
    }
}