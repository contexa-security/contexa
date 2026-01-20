package io.contexa.contexaiam.security.xacml.pap.service;

import io.contexa.contexaiam.domain.dto.BusinessPolicyDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;


public interface BusinessPolicyService {


    
    Policy createPolicyFromBusinessRule(BusinessPolicyDto dto);

    
    Policy updatePolicyFromBusinessRule(Long policyId, BusinessPolicyDto dto);

    BusinessPolicyDto getBusinessRuleForPolicy(Long policyId);

    
    BusinessPolicyDto translatePolicyToBusinessRule(Long policyId);

}
