package io.contexa.contexaiam.admin.web.monitoring.dto;

import java.util.List;

public record PolicyStatusDto(
        long totalPolicies,
        long activePolicies,
        long inactivePolicies,
        long manualPolicies,
        long aiGeneratedPolicies,
        long aiEvolvedPolicies,
        long importedPolicies,
        long pendingApproval,
        long approvedPolicies,
        long rejectedPolicies,
        long notRequiredApproval,
        Double averageAiConfidence,
        List<RecentPolicyDto> recentPolicies
) {}
