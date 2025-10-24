package io.contexa.contexaiam.admin.web.monitoring.dto;

import io.contexa.contexaiam.admin.support.context.dto.RecentActivityDto;
import java.util.List;

/**
 * [최종 확정] 대시보드 View에 최적화된 데이터를 담는 DTO.
 * 권한 매트릭스를 포함한 모든 필드를 명확하게 정의합니다.
 */
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