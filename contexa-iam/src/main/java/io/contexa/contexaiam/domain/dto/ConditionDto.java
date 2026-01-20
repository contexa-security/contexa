package io.contexa.contexaiam.domain.dto;

import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ConditionDto {
    private String expression;
    private PolicyCondition.AuthorizationPhase authorizationPhase;
} 