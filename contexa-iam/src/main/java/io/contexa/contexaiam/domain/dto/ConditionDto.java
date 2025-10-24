package io.contexa.contexaiam.domain.dto;

import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 정책 조건 DTO
 * SRP 준수: 정책 조건 데이터만 담당
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ConditionDto {
    private String expression;
    private PolicyCondition.AuthorizationPhase authorizationPhase;
} 