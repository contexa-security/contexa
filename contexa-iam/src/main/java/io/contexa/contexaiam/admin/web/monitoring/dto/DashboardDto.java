package io.contexa.contexaiam.admin.web.monitoring.dto;

import io.contexa.contexaiam.admin.support.context.dto.RecentActivityDto;
import java.util.List;


public record DashboardDto(
        long totalUserCount,
        long activeSessionCount,
        long inactiveUserCount,
        long mfaMissingAdminCount,
        List<RecentActivityDto> recentActivities,
        List<RiskIndicatorDto> riskIndicators,
        SecurityScoreDto securityScore,
        PermissionMatrixDto permissionMatrix
) {}