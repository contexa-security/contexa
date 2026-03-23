package io.contexa.contexaiam.security.xacml.pap.service;

import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexacommon.entity.Permission;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

public interface PolicyService {
    List<Policy> getAllPolicies();
    Page<Policy> searchPolicies(String keyword, Pageable pageable);
    Policy findById(Long id);
    Policy createPolicy(PolicyDto policyDto);
    void updatePolicy(PolicyDto policyDto);
    void deletePolicy(Long id);
    void synchronizePolicyForPermission(Permission permission);
    void approvePolicy(Long id, String approver);
    void rejectPolicy(Long id, String rejector);
}