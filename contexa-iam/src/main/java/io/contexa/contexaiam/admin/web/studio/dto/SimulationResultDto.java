package io.contexa.contexaiam.admin.web.studio.dto;

import java.util.List;

/**
 * 정책 시뮬레이션 결과를 담는 DTO 입니다.
 */
public record SimulationResultDto(
        String summary, // "총 5명의 사용자와 2개의 그룹의 권한이 변경됩니다." 와 같은 요약
        List<ImpactDetail> impactDetails // 상세 변경 내역
) {
    public record ImpactDetail(
            String subjectName,    // 영향을 받는 주체 (사용자/그룹)
            String subjectType,
            String permissionName, // 영향을 받는 권한
            String permissionDescription,
            ImpactType impactType, // GAIN (획득), LOSE (상실)
            String reason          // 변경 원인이 되는 정책 이름
    ) {}

    public enum ImpactType {
        PERMISSION_GAINED,
        PERMISSION_LOST
    }
}