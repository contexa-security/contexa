package io.contexa.contexaiam.admin.web.studio.dto;

/**
 * 특정 주체가 보유한 유효 권한과 그 근거를 담는 DTO 입니다.
 */
public record EffectivePermissionDto(
        String permissionName,
        String permissionDescription,
        String origin // 예: "역할: 관리자", "그룹: 해당부서"
) {}