package io.contexa.contexaiam.security.xacml.pap.service;

import io.contexa.contexaiam.domain.dto.BusinessPolicyDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;

/**
 * 컨트롤러의 요청을 받아 비즈니스 정책의 생명주기를 관리하는 메인 서비스.
 * PolicyGenerationService, DefaultPolicyService 등 다른 서비스를 조율한다.
 */
public interface BusinessPolicyService {


    /**
     * 비즈니스 규칙 DTO를 받아 새로운 정책을 생성하고 저장한다.
     * @param dto 사용자가 UI에서 입력한 비즈니스 정책 정보
     * @return 생성된 Policy 엔티티
     */
    Policy createPolicyFromBusinessRule(BusinessPolicyDto dto);

    /**
     * 비즈니스 규칙 DTO를 받아 기존 정책을 수정하고 저장한다.
     * @param policyId 수정할 정책의 ID
     * @param dto 사용자가 UI에서 수정한 비즈니스 정책 정보
     * @return 수정된 Policy 엔티티
     */
    Policy updatePolicyFromBusinessRule(Long policyId, BusinessPolicyDto dto);

    BusinessPolicyDto getBusinessRuleForPolicy(Long policyId);

    /**
     * [시그니처 개선] 기존 기술 정책(Policy)을 분석하여 정책 저작 워크벤치 UI에 표시할 수 있는
     * 사용자 친화적인 BusinessPolicyDto로 '역번역'합니다.
     * @param policyId 조회할 정책의 ID
     * @return 변환된 BusinessPolicyDto
     */
    BusinessPolicyDto translatePolicyToBusinessRule(Long policyId);

}
