package io.contexa.contexaiam.admin.web.monitoring.dto;

import java.util.List;

public record PolicyStatusDto(
        long totalPolicies,
        long activePolicies,
        long manualPolicies,
        long aiGeneratedPolicies,
        long aiEvolvedPolicies,
        long pendingApproval,
        long approvedPolicies,
        long rejectedPolicies,
        Double averageAiConfidence,
        List<RecentPolicyDto> recentPolicies
) {}
