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
import io.contexa.contexacommon.entity.RolePermission;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.center.dto.ConditionTemplateDto;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.*;
import io.contexa.contexaiam.admin.web.center.dto.PolicyResourceSearchRequest;
import io.contexa.contexaiam.admin.web.center.dto.PolicySummaryDto;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexaiam.domain.entity.SecuritySpel;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyVersion;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.SecuritySpelRepository;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyVersionService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.time.LocalDateTime;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("PolicyCenterQueryService")
class PolicyCenterQueryServiceTest {

    @Mock private ResourceRegistryService resourceRegistryService;
    @Mock private RoleService roleService;
    @Mock private PermissionCatalogService permissionCatalogService;
    @Mock private ConditionTemplateRepository conditionTemplateRepository;
    @Mock private ManagedResourceRepository managedResourceRepository;
    @Mock private SecuritySpelRepository securitySpelRepository;
    @Mock private PolicyRepository policyRepository;
    @Mock private PolicyService policyService;
    @Mock private PolicyVersionService policyVersionService;

    @InjectMocks
    private PolicyCenterQueryService service;

    @Test
    @DisplayName("searchRoles should return mapped roles page")
    void searchRoles() {
        PageRequest pageable = PageRequest.of(0, 10);
        Role role = Role.builder().id(1L).roleName("ADMIN").build();
        when(roleService.searchRoles("admin", pageable)).thenReturn(new PageImpl<>(List.of(role)));

        PolicyPageResponse<PolicyRoleResponse> res = service.searchRoles("admin", pageable);

        assertThat(res.content()).hasSize(1);
        assertThat(res.content().get(0).roleName()).isEqualTo("ADMIN");
    }

    @Nested
    @DisplayName("getAvailablePermissions")
    class GetAvailablePermissions {

        @Test
        @DisplayName("should map role and search permissions")
        void success() {
            PageRequest pageable = PageRequest.of(0, 10);
            Permission perm = Permission.builder().id(5L).name("P5").build();
            Role role = Role.builder().id(1L).roleName("ADMIN").build();
            role.setRolePermissions(Set.of(RolePermission.builder().role(role).permission(perm).build()));

            when(roleService.getRole(1L)).thenReturn(role);

            PermissionDto permDto = PermissionDto.builder().id(2L).name("P2").build();
            when(permissionCatalogService.searchAvailablePermissions(eq("keyword"), any(), eq(pageable)))
                    .thenReturn(new PageImpl<>(List.of(permDto)));

            PolicyAvailablePermissionsResponse res = service.getAvailablePermissions(List.of(1L), "keyword", pageable);

            assertThat(res.content()).hasSize(1);
            assertThat(res.content().get(0).name()).isEqualTo("P2");
            assertThat(res.alreadyMappedIds()).contains(5L);
            assertThat(res.rolePermissionMap().get("1")).containsExactly(5L);
        }
    }

    @Test
    @DisplayName("searchResources should return mapped resources page")
    void searchResources() {
        PageRequest pageable = PageRequest.of(0, 10);
        PolicyResourceSearchRequest criteria = new PolicyResourceSearchRequest();
        ManagedResource resource = ManagedResource.builder().id(100L).resourceIdentifier("/api").build();

        when(resourceRegistryService.findResources(any(), eq(pageable))).thenReturn(new PageImpl<>(List.of(resource)));

        PolicyPageResponse<PolicyResourceResponse> res = service.searchResources(criteria, pageable);

        assertThat(res.content()).hasSize(1);
        assertThat(res.content().get(0).resourceIdentifier()).isEqualTo("/api");
    }

    @Test
    @DisplayName("getSystemStats should aggregate counts")
    void getSystemStats() {
        when(roleService.getRoles()).thenReturn(List.of(new Role(), new Role()));
        when(permissionCatalogService.getAvailablePermissions()).thenReturn(List.of(new PermissionDto()));
        when(conditionTemplateRepository.count()).thenReturn(5L);
        when(policyRepository.count()).thenReturn(3L);
        when(managedResourceRepository.count()).thenReturn(10L);
        when(managedResourceRepository.countByStatus(ManagedResource.Status.NEEDS_DEFINITION)).thenReturn(4L);

        PolicySystemStatsResponse stats = service.getSystemStats();

        assertThat(stats.roleCount()).isEqualTo(2L);
        assertThat(stats.permissionCount()).isEqualTo(1L);
        assertThat(stats.conditionCount()).isEqualTo(5L);
        assertThat(stats.policyCount()).isEqualTo(3L);
        assertThat(stats.resourceTotal()).isEqualTo(10L);
        assertThat(stats.resourceNeedsDefinition()).isEqualTo(4L);
    }

    @Test
    @DisplayName("getSpelPermissions should query securitySpelRepository")
    void getSpelPermissions() {
        SecuritySpel spel = new SecuritySpel();
        spel.setId(1L);
        spel.setName("SP");
        when(securitySpelRepository.search("%keyword%")).thenReturn(List.of(spel));

        List<PolicySpelPermissionResponse> res = service.getSpelPermissions("keyword");

        assertThat(res).hasSize(1);
        assertThat(res.get(0).name()).isEqualTo("SP");
    }

    @Test
    @DisplayName("getPolicySummaries should return policies summary DTO list")
    void getPolicySummaries() {
        Policy policy = Policy.builder().id(1L).name("P1").effect(Policy.Effect.ALLOW).build();
        when(policyService.getAllPolicies()).thenReturn(List.of(policy));

        List<PolicySummaryDto> res = service.getPolicySummaries();

        assertThat(res).hasSize(1);
        assertThat(res.get(0).getName()).isEqualTo("P1");
    }

    @Test
    @DisplayName("getConditions should query conditionTemplateRepository and filter by keyword")
    void getConditions() {
        ConditionTemplate ct1 = ConditionTemplate.builder().id(1L).name("T1").description("Desc1").build();
        ConditionTemplate ct2 = ConditionTemplate.builder().id(2L).name("T2").description("Other").build();

        when(conditionTemplateRepository.findAll()).thenReturn(List.of(ct1, ct2));

        List<ConditionTemplateDto> res = service.getConditions("Desc");

        assertThat(res).hasSize(1);
        assertThat(res.get(0).getName()).isEqualTo("T1");
    }

    @Nested
    @DisplayName("getVersionSnapshot")
    class GetVersionSnapshot {

        @Test
        @DisplayName("should throw exception when version is not found")
        void notFound() {
            when(policyVersionService.getVersion(1L, 2)).thenReturn(Optional.empty());

            assertThrows(IllegalArgumentException.class, () -> service.getVersionSnapshot(1L, 2));
        }

        @Test
        @DisplayName("should return mapped snapshot response")
        void success() {
            PolicyVersion version = PolicyVersion.builder()
                    .versionNumber(2)
                    .changeType(PolicyVersion.ChangeType.UPDATED)
                    .changedBy("user")
                    .snapshotJson("{}")
                    .build();

            when(policyVersionService.getVersion(1L, 2)).thenReturn(Optional.of(version));

            PolicyVersionSnapshotResponse res = service.getVersionSnapshot(1L, 2);

            assertThat(res.versionNumber()).isEqualTo(2);
            assertThat(res.changeType()).isEqualTo("UPDATED");
            assertThat(res.snapshot()).isEqualTo("{}");
        }
    }
}
