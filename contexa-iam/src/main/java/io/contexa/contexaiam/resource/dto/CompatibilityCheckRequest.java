package io.contexa.contexaiam.resource.dto;

/**
 * 호환성 검사 요청 DTO
 * SRP 준수: 호환성 검사 요청 정보만 담당
 */
public class CompatibilityCheckRequest {
    public Long conditionId;
    public Long resourceId;
} 