package io.contexa.contexaiam.admin.web.monitoring.dto;

import java.util.List;
import java.util.Map;

/**
 * 권한 매트릭스 시각화를 위한 데이터를 담는 DTO 입니다.
 */
public record PermissionMatrixDto(
        List<String> subjects, // 행 (예: 그룹명, 역할명)
        List<String> permissions, // 열 (예: 권한 설명)
        Map<String, Map<String, String>> matrixData // "subject: { permission: 'GRANT' | 'DENY' | 'NONE' }"
) {}
