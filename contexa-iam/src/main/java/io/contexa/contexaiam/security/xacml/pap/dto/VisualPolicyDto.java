package io.contexa.contexaiam.security.xacml.pap.dto;

import io.contexa.contexaiam.domain.entity.policy.Policy;

import java.util.Map;
import java.util.Set;

/**
 * 시각적 정책 빌더 UI에서 구성된 요소를 담는 DTO 입니다.
 * PermissionWizardService의 WizardContext와 유사하지만, 보다 직접적인 정책 구성을 위해 사용될 수 있습니다.
 */
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
