package io.contexa.contexaiam.security.xacml.pap.service;

import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexacommon.entity.Permission;

import java.util.List;

/**
 * PAP (Policy Administration Point) 서비스 인터페이스.
 * 정책의 생성, 수정, 삭제 등 관리 책임을 갖는다.
 */
public interface PolicyService {
    List<Policy> getAllPolicies();
    Policy findById(Long id);
    Policy createPolicy(PolicyDto policyDto);
    void updatePolicy(PolicyDto policyDto);
    void deletePolicy(Long id);
    void synchronizePolicyForPermission(Permission permission);
}