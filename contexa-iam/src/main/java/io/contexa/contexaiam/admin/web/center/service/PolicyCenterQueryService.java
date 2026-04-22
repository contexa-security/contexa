package io.contexa.contexaiam.admin.web.center.service;

import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.center.dto.ConditionTemplateDto;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyAvailablePermissionsResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyPageResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyPermissionResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyResourceResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyRoleResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicySpelPermissionResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicySystemStatsResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyVersionDiffResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyVersionSnapshotResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyVersionSummaryResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicySummaryDto;
import io.contexa.contexaiam.admin.web.center.dto.PolicyResourceSearchRequest;
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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@RequiredArgsConstructor
@Slf4j
public class PolicyCenterQueryService {

    private final ResourceRegistryService resourceRegistryService;
    private final RoleService roleService;
    private final PermissionCatalogService permissionCatalogService;
    private final ConditionTemplateRepository conditionTemplateRepository;
    private final ManagedResourceRepository managedResourceRepository;
    private final SecuritySpelRepository securitySpelRepository;
    private final PolicyRepository policyRepository;
    private final PolicyService policyService;
    private final PolicyVersionService policyVersionService;

    public PolicyPageResponse<PolicyRoleResponse> searchRoles(String keyword, Pageable pageable) {
        Page<PolicyRoleResponse> roles = roleService.searchRoles(keyword, pageable)
                .map(this::toRoleResponse);
        return toPageResponse(roles);
    }

    public PolicyAvailablePermissionsResponse getAvailablePermissions(
            List<Long> roleIds,
            String keyword,
            Pageable pageable) {
        Set<Long> allMappedPermIds = new HashSet<>();
        Map<String, List<Long>> rolePermissionMap = new LinkedHashMap<>();
        if (roleIds != null) {
            for (Long roleId : roleIds) {
                if (roleId == null || roleId <= 0) {
                    continue;
                }
                try {
                    Role role = roleService.getRole(roleId);
                    List<Long> permIds = new ArrayList<>();
                    role.getRolePermissions().forEach(rp -> {
                        Long pid = rp.getPermission().getId();
                        allMappedPermIds.add(pid);
                        permIds.add(pid);
                    });
                    rolePermissionMap.put(String.valueOf(roleId), permIds);
                } catch (Exception e) {
                    log.error("Failed to load role {}", roleId, e);
                }
            }
        }
        Page<PolicyPermissionResponse> allPermissions = permissionCatalogService
                .searchAvailablePermissions(keyword, Collections.emptySet(), pageable)
                .map(this::toPermissionResponse);
        return new PolicyAvailablePermissionsResponse(
                allPermissions.getContent(),
                allPermissions.getTotalElements(),
                allPermissions.getTotalPages(),
                allPermissions.getNumber(),
                allPermissions.getSize(),
                allMappedPermIds,
                rolePermissionMap
        );
    }

    public PolicyPageResponse<PolicyResourceResponse> searchResources(
            PolicyResourceSearchRequest criteria,
            Pageable pageable) {
        Page<PolicyResourceResponse> resources = resourceRegistryService.findResources(criteria.toCriteria(), pageable)
                .map(this::toResourceResponse);
        return toPageResponse(resources);
    }

    public PolicySystemStatsResponse getSystemStats() {
        long roleCount = roleService.getRoles().size();
        long permissionCount = permissionCatalogService.getAvailablePermissions().size();
        long conditionCount = conditionTemplateRepository.count();
        long policyCount = policyRepository.count();
        long resourceTotal = managedResourceRepository.count();
        long resourceNeedsDefinition = managedResourceRepository.countByStatus(ManagedResource.Status.NEEDS_DEFINITION);
        long resourcePermissionCreated = managedResourceRepository.countByStatus(ManagedResource.Status.PERMISSION_CREATED);
        long resourcePolicyConnected = managedResourceRepository.countByStatus(ManagedResource.Status.POLICY_CONNECTED);

        return new PolicySystemStatsResponse(
                roleCount,
                permissionCount,
                conditionCount,
                policyCount,
                resourceTotal,
                resourceNeedsDefinition,
                resourcePermissionCreated,
                resourcePolicyConnected
        );
    }

    public List<PolicySpelPermissionResponse> getSpelPermissions(String keyword) {
        String pattern = (keyword != null && !keyword.isBlank()) ? "%" + keyword.toLowerCase() + "%" : null;
        return securitySpelRepository.search(pattern).stream()
                .map(this::toSpelPermissionResponse)
                .toList();
    }

    public List<PolicySummaryDto> getPolicySummaries() {
        return policyService.getAllPolicies().stream()
                .map(p -> PolicySummaryDto.builder()
                        .id(p.getId())
                        .name(p.getName())
                        .effect(p.getEffect() != null ? p.getEffect().name() : "ALLOW")
                        .build())
                .toList();
    }

    public List<ConditionTemplateDto> getConditions(String keyword) {
        return conditionTemplateRepository.findAll().stream()
                .filter(ct -> keyword == null || keyword.isBlank()
                        || lowerContains(ct.getName(), keyword)
                        || lowerContains(ct.getDescription(), keyword))
                .map(this::toConditionTemplateDto)
                .toList();
    }

    public List<PolicyVersionSummaryResponse> getVersions(Long policyId) {
        return policyService.getVersions(policyId).stream()
                .map(this::toVersionSummaryResponse)
                .toList();
    }

    public PolicyVersionSnapshotResponse getVersionSnapshot(Long policyId, int versionNumber) {
        PolicyVersion version = policyVersionService.getVersion(policyId, versionNumber)
                .orElseThrow(() -> new IllegalArgumentException("Version not found"));
        return new PolicyVersionSnapshotResponse(
                version.getVersionNumber(),
                enumName(version.getChangeType()),
                version.getChangedBy(),
                version.getChangeReason(),
                version.getChangedAt() != null ? version.getChangedAt().toString() : null,
                version.getSnapshotJson(),
                null
        );
    }

    public List<PolicyVersionDiffResponse> compareVersions(Long policyId, int v1, int v2) {
        return policyVersionService.compareVersions(policyId, v1, v2).stream()
                .map(change -> new PolicyVersionDiffResponse(
                        change.get("field"),
                        change.get("before"),
                        change.get("after")))
                .toList();
    }

    private <T> PolicyPageResponse<T> toPageResponse(Page<T> page) {
        return new PolicyPageResponse<>(
                page.getContent(),
                page.getTotalElements(),
                page.getTotalPages(),
                page.getNumber(),
                page.getSize()
        );
    }

    private PolicyRoleResponse toRoleResponse(Role role) {
        return new PolicyRoleResponse(
                role.getId(),
                role.getRoleName(),
                role.getRoleDesc(),
                false,
                false,
                null,
                null,
                null,
                null,
                0
        );
    }

    private PolicyPermissionResponse toPermissionResponse(PermissionDto permission) {
        return new PolicyPermissionResponse(
                permission.getId(),
                permission.getName(),
                permission.getFriendlyName(),
                permission.getDescription(),
                permission.getTargetType(),
                permission.getActionType(),
                permission.getConditionExpression(),
                permission.getManagedResourceId(),
                permission.getManagedResourceIdentifier()
        );
    }

    private PolicyResourceResponse toResourceResponse(ManagedResource resource) {
        return new PolicyResourceResponse(
                resource.getId(),
                resource.getResourceIdentifier(),
                enumName(resource.getResourceType()),
                enumName(resource.getHttpMethod()),
                resource.getFriendlyName(),
                enumName(resource.getStatus()),
                resource.getServiceOwner(),
                resource.getSourceCodeLocation(),
                resource.getApiDocsUrl(),
                resource.getDescription(),
                resource.getCreatedAt() != null ? resource.getCreatedAt().toString() : null
        );
    }

    private PolicySpelPermissionResponse toSpelPermissionResponse(SecuritySpel spel) {
        return new PolicySpelPermissionResponse(
                spel.getId(),
                spel.getName(),
                spel.getExpression(),
                spel.getDescription(),
                spel.getCategory()
        );
    }

    private ConditionTemplateDto toConditionTemplateDto(ConditionTemplate conditionTemplate) {
        return ConditionTemplateDto.builder()
                .id(conditionTemplate.getId())
                .name(conditionTemplate.getName())
                .description(conditionTemplate.getDescription())
                .category(conditionTemplate.getCategory())
                .build();
    }

    private PolicyVersionSummaryResponse toVersionSummaryResponse(PolicyVersion version) {
        return new PolicyVersionSummaryResponse(
                version.getVersionNumber(),
                enumName(version.getChangeType()),
                version.getChangedBy(),
                version.getChangeReason(),
                version.getChangedAt() != null ? version.getChangedAt().toString() : null
        );
    }

    private String enumName(Enum<?> value) {
        return value != null ? value.name() : null;
    }

    private boolean lowerContains(String value, String keyword) {
        return value != null && value.toLowerCase().contains(keyword.toLowerCase());
    }
}
