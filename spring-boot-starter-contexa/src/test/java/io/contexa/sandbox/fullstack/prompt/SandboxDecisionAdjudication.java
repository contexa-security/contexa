package io.contexa.sandbox.fullstack.prompt;

import java.util.List;

public record SandboxDecisionAdjudication(
        List<SandboxDecisionClaimAssessment> claimAssessments,
        int groundedClaimCount,
        int unsupportedClaimCount,
        int contradictedClaimCount,
        double groundedClaimPrecision,
        double unsupportedClaimRate,
        double contradictedClaimRate,
        boolean uncertaintyLanguagePresent,
        boolean requiredEvidenceCovered,
        String adjudicationVersion) {

    public SandboxDecisionAdjudication {
        claimAssessments = claimAssessments == null ? List.of() : List.copyOf(claimAssessments);
    }

    public int totalClaimCount() {
        return claimAssessments.size();
    }
}
