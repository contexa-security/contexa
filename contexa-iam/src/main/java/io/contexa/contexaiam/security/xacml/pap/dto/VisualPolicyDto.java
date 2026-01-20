package io.contexa.contexaiam.security.xacml.pap.dto;

import io.contexa.contexaiam.domain.entity.policy.Policy;

import java.util.Map;
import java.util.Set;


public record VisualPolicyDto(
        String name,
        String description,
        Policy.Effect effect,
        Set<SubjectIdentifier> subjects,
        Set<PermissionIdentifier> permissions,
        Set<ConditionIdentifier> conditions
) {
    public record SubjectIdentifier(Long id, String type) {}
    public record PermissionIdentifier(Long id) {}
    public record ConditionIdentifier(String conditionKey, Map<String, Object> params) {}
}
