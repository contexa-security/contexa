package io.contexa.contexaiam.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 정책 대상 DTO
 * SRP 준수: 정책 대상 데이터만 담당
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TargetDto {
    private String targetType;
    private String targetIdentifier;
    private String httpMethod;
} 