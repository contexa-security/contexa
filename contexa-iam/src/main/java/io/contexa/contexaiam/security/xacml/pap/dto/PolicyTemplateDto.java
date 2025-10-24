package io.contexa.contexaiam.security.xacml.pap.dto;

import io.contexa.contexaiam.domain.dto.PolicyDto;

/**
 * 자주 사용되는 정책 시나리오를 템플릿화하여 제공하기 위한 DTO 입니다.
 */
public record PolicyTemplateDto(
        String templateId,
        String name, // 예: "신입사원 기본 권한 세트"
        String description, // 예: "모든 신입사원에게 적용되는 기본적인 읽기 권한을 부여합니다."
        PolicyDto policyDraft // 이 템플릿을 선택했을 때 생성될 정책의 초안
) {}
