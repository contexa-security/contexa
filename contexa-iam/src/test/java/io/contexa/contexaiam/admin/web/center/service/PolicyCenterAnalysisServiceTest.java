/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaiam.admin.web.center.service;

import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexaiam.admin.web.center.dto.*;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.*;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyMatrixService;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexaiam.security.xacml.pap.dto.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("PolicyCenterAnalysisService")
class PolicyCenterAnalysisServiceTest {

    @Mock private PolicyService policyService;
    @Mock private PolicyValidationService policyValidationService;
    @Mock private PermissionRepository permissionRepository;
    @Mock private PolicyMatrixService policyMatrixService;

    @InjectMocks
    private PolicyCenterAnalysisService service;

    @Test
    @DisplayName("getValidationReport should delegate to policyValidationService")
    void getValidationReport() {
        when(policyValidationService.validateAll()).thenReturn(mock(FullValidationReport.class));

        PolicyFullValidationResponse report = service.getValidationReport();

        assertThat(report).isNotNull();
        verify(policyValidationService).validateAll();
    }

    @Test
    @DisplayName("validatePolicy should delegate to policyService")
    void validatePolicy() {
        PolicyCenterPolicyRequest request = new PolicyCenterPolicyRequest();
        request.setName("P1");
        request.setEffect("ALLOW");
        request.setTargets(Collections.emptyList());

        when(policyService.validateBeforeCreate(any())).thenReturn(mock(PolicyValidationReport.class));

        PolicyValidationResponse res = service.validatePolicy(request);

        assertThat(res).isNotNull();
        verify(policyService).validateBeforeCreate(any());
    }

    @Nested
    @DisplayName("validateQuickPolicy")
    class ValidateQuickPolicy {

        @Test
        @DisplayName("should support MANUAL source type")
        void manualSource() {
            QuickPolicyRequest request = new QuickPolicyRequest();
            request.setPolicyName("QP");
            request.setEffect(Policy.Effect.ALLOW);
            request.setSourceType("MANUAL");
            request.setManualTargetType("URL");
            request.setManualTargetIdentifier("/api/v1/test");
            request.setManualHttpMethod("GET");
            request.setManualTargetOrder(1);

            when(policyService.validateBeforeCreate(any())).thenReturn(mock(PolicyValidationReport.class));

            service.validateQuickPolicy(request);

            verify(policyService).validateBeforeCreate(argThat(policy ->
                    policy.getName().equals("QP") &&
                    policy.getTargets().size() == 1 &&
                    policy.getTargets().get(0).getTargetIdentifier().equals("/api/v1/test")
            ));
        }

        @Test
        @DisplayName("should support PERMISSION source type")
        void permissionSource() {
            QuickPolicyRequest request = new QuickPolicyRequest();
            request.setPolicyName("QP2");
            request.setEffect(Policy.Effect.DENY);
            request.setSourceType("PERMISSION");
            request.setPermissionIds(Set.of(10L));

            ManagedResource mr = ManagedResource.builder()
                    .resourceType(ManagedResource.ResourceType.URL)
                    .resourceIdentifier("/api/auth")
                    .httpMethod(ManagedResource.HttpMethod.POST)
                    .build();
            Permission perm = Permission.builder().id(10L).managedResource(mr).build();

            when(permissionRepository.findById(10L)).thenReturn(Optional.of(perm));
            when(policyService.validateBeforeCreate(any())).thenReturn(mock(PolicyValidationReport.class));

            service.validateQuickPolicy(request);

            verify(policyService).validateBeforeCreate(argThat(policy ->
                    policy.getName().equals("QP2") &&
                    policy.getTargets().size() == 1 &&
                    policy.getTargets().get(0).getTargetIdentifier().equals("/api/auth") &&
                    policy.getTargets().get(0).getHttpMethod().equals("POST")
            ));
        }
    }

    @Test
    @DisplayName("validateAIPolicy should delegate to policyService")
    void validateAIPolicy() {
        when(policyService.validateAIPolicy(1L)).thenReturn(mock(AIPolicyValidationReport.class));

        PolicyAiValidationResponse res = service.validateAIPolicy(1L);

        assertThat(res).isNotNull();
        verify(policyService).validateAIPolicy(1L);
    }

    @Test
    @DisplayName("simulate should delegate to policyService")
    void simulate() {
        PolicySimulationRequest request = new PolicySimulationRequest();
        request.setCandidatePolicy(new PolicyCenterPolicyRequest());
        request.setTestCases(Collections.emptyList());

        when(policyService.simulate(any(), any())).thenReturn(mock(SimulationReport.class));

        PolicySimulationResponse res = service.simulate(request);

        assertThat(res).isNotNull();
        verify(policyService).simulate(any(), any());
    }

    @Test
    @DisplayName("analyzeImpact should delegate to policyService")
    void analyzeImpact() {
        PolicyCenterPolicyRequest request = new PolicyCenterPolicyRequest();
        request.setTargets(Collections.emptyList());

        when(policyService.analyzeImpact(any())).thenReturn(mock(PolicyImpactReport.class));

        PolicyImpactResponse res = service.analyzeImpact(request);

        assertThat(res).isNotNull();
        verify(policyService).analyzeImpact(any());
    }

    @Test
    @DisplayName("getMatrix should delegate to policyMatrixService")
    void getMatrix() {
        when(policyMatrixService.generateMatrix("r", "role")).thenReturn(mock(PolicyMatrixReport.class));

        PolicyMatrixResponse res = service.getMatrix("r", "role");

        assertThat(res).isNotNull();
        verify(policyMatrixService).generateMatrix("r", "role");
    }
}
