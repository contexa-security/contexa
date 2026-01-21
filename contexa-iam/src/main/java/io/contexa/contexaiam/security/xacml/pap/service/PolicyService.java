package io.contexa.contexaiam.security.xacml.pap.service;

import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexacommon.entity.Permission;

import java.util.List;

public interface PolicyService {
    List<Policy> getAllPolicies();
    Policy findById(Long id);
    Policy createPolicy(PolicyDto policyDto);
    void updatePolicy(PolicyDto policyDto);
    void deletePolicy(Long id);
    void synchronizePolicyForPermission(Permission permission);
}