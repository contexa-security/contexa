package io.contexa.contexaiam.admin.web.monitoring.dto;

import io.contexa.contexaiam.admin.support.context.dto.RecentActivityDto;
import java.util.List;

public record DashboardDto(
        StatisticsDto statistics,
        List<RecentActivityDto> recentActivities,
        List<RiskIndicatorDto> riskIndicators,
        SecurityScoreDto securityScore,
        PermissionMatrixDto permissionMatrix,
        PolicyStatusDto policyStatus,
        List<AccessTrendDto> accessTrends
) {}
