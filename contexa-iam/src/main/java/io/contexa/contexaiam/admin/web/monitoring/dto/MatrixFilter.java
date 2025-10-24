package io.contexa.contexaiam.admin.web.monitoring.dto;

import java.util.Set;

/**
 * 권한 매트릭스 조회 시 사용할 필터 DTO 입니다.
 */
public record MatrixFilter(Set<Long> subjectIds, Set<Long> permissionIds, String subjectType) {}