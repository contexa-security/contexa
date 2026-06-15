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
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.center.dto.BatchCreateRequest;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.*;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterPolicyRequest;
import io.contexa.contexaiam.admin.web.center.dto.QuickPolicyRequest;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyValidationReport;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pap.service.BusinessPolicyService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyEnrichmentService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyVersionService;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.MessageSource;
import org.springframework.dao.DataIntegrityViolationException;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("PolicyCenterCommandService")
class PolicyCenterCommandServiceTest {

    @Mock private ResourceRegistryService resourceRegistryService;
    @Mock private PolicyService policyService;
    @Mock private PolicyRepository policyRepository;
    @Mock private RoleService roleService;
    @Mock private BusinessPolicyService businessPolicyService;
    @Mock private ManagedResourceRepository managedResourceRepository;
    @Mock private PermissionRepository permissionRepository;
    @Mock private PolicyValidationService policyValidationService;
    @Mock private PolicyEnrichmentService policyEnrichmentService;
    @Mock private PolicyVersionService policyVersionService;
    @Mock private CustomDynamicAuthorizationManager authorizationManager;
    @Mock private CentralAuditFacade centralAuditFacade;
    @Mock private MessageSource messageSource;

    @InjectMocks
    private PolicyCenterCommandService service;

    @BeforeEach
    void setUp() {
        when(messageSource.getMessage(anyString(), any(), any(Locale.class)))
                .thenAnswer(inv -> inv.getArgument(0));
    }

    @Nested
    @DisplayName("refreshResources")
    class RefreshResources {
        @Test
        @DisplayName("should refresh resources and enrich policies with null description")
        void success() {
            Policy policy = new Policy();
            when(policyRepository.findByFriendlyDescriptionIsNull()).thenReturn(List.of(policy));

            service.refreshResources();

            verify(resourceRegistryService).refreshAndSynchronizeResources();
            verify(policyEnrichmentService).enrichPolicyWithFriendlyDescription(policy);
            verify(policyRepository).save(policy);
        }
    }

    @Nested
    @DisplayName("createPolicyFromCenter")
    class CreatePolicy {
        @Test
        @DisplayName("should return success when creation succeeds")
        void success() {
            PolicyCenterPolicyRequest request = new PolicyCenterPolicyRequest();
            request.setName("P1");
            request.setTargets(List.of());

            PolicyActionResponse res = service.createPolicyFromCenter(request);

            assertThat(res.success()).isTrue();
            assertThat(res.message()).isEqualTo("msg.policy.created");
        }

        @Test
        @DisplayName("should return duplicate warning on DataIntegrityViolationException")
        void duplicateName() {
            PolicyCenterPolicyRequest request = new PolicyCenterPolicyRequest();
            request.setTargets(List.of());
            doThrow(new DataIntegrityViolationException("")).when(policyService).createPolicy(any());

            PolicyActionResponse res = service.createPolicyFromCenter(request);

            assertThat(res.success()).isFalse();
            assertThat(res.message()).isEqualTo("msg.policy.name.duplicate");
        }
    }

    @Nested
    @DisplayName("quickCreatePolicy")
    class QuickCreate {
        @Test
        @DisplayName("should create policy and check duplicate warning")
        void success() {
            QuickPolicyRequest request = new QuickPolicyRequest();
            request.setPolicyName("Q1");
            request.setRoleIds(Set.of(10L));
            request.setPermissionIds(Set.of());

            Role role = Role.builder().id(10L).roleName("USER").build();
            when(roleService.getRole(10L)).thenReturn(role);
            when(policyRepository.findByName("AUTO_POLICY_FOR_USER")).thenReturn(Optional.of(new Policy()));
            when(businessPolicyService.createPolicyFromBusinessRule(any())).thenReturn(Policy.builder().id(5L).build());

            PolicyQuickCreateResponse res = service.quickCreatePolicy(request);

            assertThat(res.success()).isTrue();
            assertThat(res.policyId()).isEqualTo(5L);
            assertThat(res.warning()).isEqualTo("msg.policy.auto.duplicate.warning");
        }
    }

    @Nested
    @DisplayName("resetPolicyStatus")
    class ResetPolicyStatus {
        @Test
        @DisplayName("should skip when resourceIds is empty")
        void empty() {
            PolicyActionResponse res = service.resetPolicyStatus(Collections.emptyList());
            assertThat(res.success()).isFalse();
        }

        @Test
        @DisplayName("should reset status to NEEDS_DEFINITION and delete linked permissions")
        void success() {
            Permission perm = Permission.builder().id(100L).build();
            ManagedResource resource = ManagedResource.builder()
                    .id(1L)
                    .status(ManagedResource.Status.PERMISSION_CREATED)
                    .permission(perm)
                    .build();

            when(managedResourceRepository.findById(1L)).thenReturn(Optional.of(resource));

            PolicyActionResponse res = service.resetPolicyStatus(List.of(1L));

            assertThat(res.success()).isTrue();
            assertThat(resource.getStatus()).isEqualTo(ManagedResource.Status.NEEDS_DEFINITION);
            verify(permissionRepository).deleteById(100L);
        }
    }

    @Nested
    @DisplayName("batchCreatePolicies")
    class BatchCreate {
        @Test
        @DisplayName("should validate empty request")
        void empty() {
            PolicyBatchCreateResponse res = service.batchCreatePolicies(new BatchCreateRequest());
            assertThat(res.success()).isFalse();
            assertThat(res.message()).isEqualTo("msg.policy.validation.target.required");
        }

        @Test
        @DisplayName("should create batch policies successfully and skip duplicates")
        void success() {
            BatchCreateRequest.BatchItem item1 = new BatchCreateRequest.BatchItem();
            item1.setResourceIdentifier("/api/test");
            item1.setCrudPermissions(Set.of("READ"));

            BatchCreateRequest.BatchItem item2 = new BatchCreateRequest.BatchItem();
            item2.setResourceIdentifier("/api/test2");
            item2.setCrudPermissions(Set.of("WRITE"));

            BatchCreateRequest request = new BatchCreateRequest();
            request.setItems(List.of(item1, item2));
            request.setRoleIds(Set.of(10L));
            request.setEffect(Policy.Effect.ALLOW);

            Role role = Role.builder().id(10L).roleName("USER").build();
            when(roleService.getRole(10L)).thenReturn(role);
            when(policyRepository.findAllWithDetails()).thenReturn(new ArrayList<>());

            PolicyValidationReport rep1 = mock(PolicyValidationReport.class);
            when(rep1.canCreate()).thenReturn(true);
            PolicyValidationReport rep2 = mock(PolicyValidationReport.class);
            when(rep2.canCreate()).thenReturn(false);
            when(rep2.blockedReason()).thenReturn("Blocked duplicate");

            when(policyValidationService.validate(any(), any()))
                    .thenReturn(rep1)
                    .thenReturn(rep2);

            when(policyRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

            PolicyBatchCreateResponse res = service.batchCreatePolicies(request);

            assertThat(res.success()).isTrue();
            assertThat(res.created()).isEqualTo(1);
            assertThat(res.results()).hasSize(2);
            assertThat(res.results().get(0).status()).isEqualTo("CREATED");
            assertThat(res.results().get(1).status()).isEqualTo("SKIPPED");
        }
    }

    @Nested
    @DisplayName("cleanupOldAutoCreatedPermissions")
    class CleanupPermissions {
        @Test
        @DisplayName("should remove autoCreated old permissions")
        void success() {
            Permission perm1 = Permission.builder().id(1L).name("URL_GET_TEST").autoCreated(true).build();
            Permission perm2 = Permission.builder().id(2L).name("READ_USER").autoCreated(false).build();

            when(permissionRepository.findAll()).thenReturn(List.of(perm1, perm2));

            PolicyCleanupResponse res = service.cleanupOldAutoCreatedPermissions();

            assertThat(res.success()).isTrue();
            assertThat(res.deleted()).isEqualTo(1);
            verify(permissionRepository).deleteAllByIds(List.of(1L));
        }
    }

    @Nested
    @DisplayName("rollbackPolicy")
    class RollbackPolicy {
        @Test
        @DisplayName("should invoke policyService.rollbackPolicy")
        void success() {
            PolicyRollbackRequest request = new PolicyRollbackRequest("My Reason");

            PolicyActionResponse res = service.rollbackPolicy(1L, 3, request);

            assertThat(res.success()).isTrue();
            verify(policyService).rollbackPolicy(1L, 3, "My Reason");
        }
    }
}
