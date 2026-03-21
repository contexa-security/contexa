package io.contexa.contexaiam.admin.web.monitoring.dto;

import io.contexa.contexaiam.admin.support.context.dto.RecentActivityDto;
import io.contexa.contexaiam.domain.entity.BlockedUser;
import io.contexa.contexacommon.entity.AuditLog;
import java.util.List;

public record DashboardDto(
        StatisticsDto statistics,
        List<RecentActivityDto> recentActivities,
        List<RiskIndicatorDto> riskIndicators,
        SecurityScoreDto securityScore,
        PermissionMatrixDto permissionMatrix,
        PolicyStatusDto policyStatus,
        List<AccessTrendDto> accessTrends,
        long resourceTotal,
        long resourceProtected,
        long resourceAwaiting,
        long blockedUserCount,
        long unblockRequestedCount,
        long soarAutoResponseCount,
        long mfaFailedCount,
        long resolvedCount,
        List<BlockedUser> recentBlockedUsers,
        // 24h security activity from audit_log
        long allowCount24h,
        long denyCount24h,
        long authSuccessCount24h,
        long authFailureCount24h,
        long securityDecisionCount24h,
        long adminOverrideCount24h,
        long securityErrorCount24h,
        long afterHoursAccessCount24h,
        long distinctIpCount24h,
        Double avgRiskScore24h,
        // Zero Trust decision breakdown
        long challengeCount24h,
        long blockCount24h,
        long escalateCount24h,
        long policyChangeCount24h,
        long iamChangeCount24h,
        List<AuditLog> recentThreatEvents
) {}
