package io.contexa.contexaiam.security.xacml.pap.service;

import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyVersion;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyConflictDto;
import io.contexa.contexaiam.security.xacml.pap.dto.AIPolicyValidationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyImpactReport;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyValidationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationTestCase;
import io.contexa.contexacommon.entity.Permission;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

public interface PolicyService {
    List<Policy> getAllPolicies();
    Page<Policy> searchPolicies(String keyword, Pageable pageable);
    Page<Policy> searchPolicies(String keyword, Policy.ApprovalStatus approvalStatus, Boolean activeFilter, Pageable pageable);
    Policy findById(Long id);
    Policy createPolicy(PolicyDto policyDto);
    void updatePolicy(PolicyDto policyDto);
    void deletePolicy(Long id);
    void deletePolicy(Long id, String changeReason);
    void synchronizePolicyForPermission(Permission permission);
    void approvePolicy(Long id, String approver);
    void rejectPolicy(Long id, String rejector);
    List<PolicyConflictDto> detectConflicts(PolicyDto policyDto);
    PolicyValidationReport validateBeforeCreate(PolicyDto policyDto);
    List<PolicyVersion> getVersions(Long policyId);
    Policy rollbackPolicy(Long policyId, int versionNumber, String reason);
    PolicyImpactReport analyzeImpact(PolicyDto policyDto);
    SimulationReport simulate(PolicyDto candidatePolicy, List<SimulationTestCase> testCases);
    AIPolicyValidationReport validateAIPolicy(Long policyId);
}