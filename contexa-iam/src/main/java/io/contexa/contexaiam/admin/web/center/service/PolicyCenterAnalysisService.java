package io.contexa.contexaiam.admin.web.center.service;

import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyAiValidationResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyFullValidationResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyImpactResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyMatrixResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicySimulationResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyValidationResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterPolicyRequest;
import io.contexa.contexaiam.admin.web.center.dto.PolicySimulationRequest;
import io.contexa.contexaiam.admin.web.center.dto.QuickPolicyRequest;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.dto.TargetDto;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyMatrixService;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import lombok.RequiredArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@RequiredArgsConstructor
public class PolicyCenterAnalysisService {

    private final PolicyService policyService;
    private final PolicyValidationService policyValidationService;
    private final PermissionRepository permissionRepository;
    private final PolicyMatrixService policyMatrixService;

    public PolicyFullValidationResponse getValidationReport() {
        return PolicyFullValidationResponse.from(policyValidationService.validateAll());
    }

    public PolicyValidationResponse validatePolicy(PolicyCenterPolicyRequest request) {
        return PolicyValidationResponse.from(policyService.validateBeforeCreate(request.toPolicyDto()));
    }

    public PolicyValidationResponse validateQuickPolicy(QuickPolicyRequest request) {
        PolicyDto policyDto = PolicyDto.builder()
                .name(request.getPolicyName())
                .description(request.getDescription())
                .effect(request.getEffect())
                .priority(100)
                .build();

        if ("MANUAL".equals(request.getSourceType())
                && request.getManualTargetIdentifier() != null) {
            policyDto.setTargets(List.of(TargetDto.builder()
                    .targetType(request.getManualTargetType())
                    .targetIdentifier(request.getManualTargetIdentifier())
                    .httpMethod(request.getManualHttpMethod())
                    .targetOrder(request.getManualTargetOrder())
                    .build()));
        } else if (request.getPermissionIds() != null) {
            List<TargetDto> targets = new ArrayList<>();
            for (Long permId : request.getPermissionIds()) {
                permissionRepository.findById(permId).ifPresent(perm -> {
                    ManagedResource managedResource = perm.getManagedResource();
                    if (managedResource != null) {
                        targets.add(TargetDto.builder()
                                .targetType(managedResource.getResourceType().name())
                                .targetIdentifier(managedResource.getResourceIdentifier())
                                .httpMethod(managedResource.getHttpMethod() != null
                                        ? managedResource.getHttpMethod().name()
                                        : "ANY")
                                .build());
                    }
                });
            }
            policyDto.setTargets(targets);
        }

        return PolicyValidationResponse.from(policyService.validateBeforeCreate(policyDto));
    }

    public PolicyAiValidationResponse validateAIPolicy(Long policyId) {
        return PolicyAiValidationResponse.from(policyService.validateAIPolicy(policyId));
    }

    public PolicySimulationResponse simulate(PolicySimulationRequest request) {
        return PolicySimulationResponse.from(policyService.simulate(
                request.toCandidatePolicyDto(),
                request.toSimulationTestCases()));
    }

    public PolicyImpactResponse analyzeImpact(PolicyCenterPolicyRequest request) {
        return PolicyImpactResponse.from(policyService.analyzeImpact(request.toPolicyDto()));
    }

    public PolicyMatrixResponse getMatrix(String resourceFilter, String roleFilter) {
        return PolicyMatrixResponse.from(policyMatrixService.generateMatrix(resourceFilter, roleFilter));
    }
}
