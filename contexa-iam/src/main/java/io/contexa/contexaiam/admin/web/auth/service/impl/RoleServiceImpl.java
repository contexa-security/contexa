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
package io.contexa.contexaiam.admin.web.auth.service.impl;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexaiam.admin.web.auth.dto.AffectedPolicyDtos.AffectedPoliciesResponse;
import io.contexa.contexaiam.admin.web.auth.dto.AffectedPolicyDtos.AffectedPolicyResponse;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacommon.entity.RolePermission;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.common.event.dto.RolePermissionsChangedEvent;
import io.contexa.contexaiam.common.event.service.IntegrationEventBus;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.RoleHierarchyRepository;
import io.contexa.contexaiam.security.xacml.pap.service.PolicySynchronizationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final IntegrationEventBus eventBus;
    private final CentralAuditFacade centralAuditFacade;
    private final RoleHierarchyRepository roleHierarchyRepository;
    private final PolicyRepository policyRepository;
    private final PolicySynchronizationService policySynchronizationService;
    private final MessageSource messageSource;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    @Cacheable(value = "roles", key = "#id")
    public Role getRole(long id) {
        return roleRepository.findByIdWithPermissions(id)
                .orElseThrow(() -> new IllegalArgumentException(msg("msg.role.not.found.id", id)));
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    @Cacheable(value = "roles", key = "'allRoles'")
    public List<Role> getRoles() {
        return roleRepository.findAllWithPermissions();
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    @Cacheable(value = "rolesWithoutExpression", key = "'allRolesWithoutExpression'")
    public List<Role> getRolesWithoutExpression() {
        return roleRepository.findAllRolesWithoutExpression();
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    @Protectable(verificationRequired = false)
    public Page<Role> searchRoles(String keyword, Pageable pageable) {
        String effectiveKeyword = StringUtils.hasText(keyword) ? keyword.trim() : null;
        Pageable effectivePageable = PageRequest.of(pageable.getPageNumber(), pageable.getPageSize());
        return roleRepository.searchByKeyword(effectiveKeyword, effectivePageable);
    }
    @Override
    public Optional<AffectedPoliciesResponse> getAffectedPolicies(Long id) {
        return roleRepository.findById(id)
                .map(role -> {
                    List<AffectedPolicyResponse> policyList = policyRepository
                            .findActivePoliciesReferencingExpression(role.getRoleName())
                            .stream()
                            .map(AffectedPolicyResponse::from)
                            .toList();
                    return AffectedPoliciesResponse.forRole(role.getRoleName(), policyList);
                });
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithAuthorities", allEntries = true),
                    @CacheEvict(value = "roles", allEntries = true),
                    @CacheEvict(value = "rolesWithoutExpression", allEntries = true)
            },
            put = {@CachePut(value = "roles", key = "#result.id")}
    )
    public Role createRole(Role role, List<Long> permissionIds) {
        if (roleRepository.findByRoleName(role.getRoleName()).isPresent()) {
            throw new IllegalArgumentException(msg("msg.role.name.duplicate", role.getRoleName()));
        }

        if (permissionIds != null && !permissionIds.isEmpty()) {
            List<Permission> permissions = permissionRepository.findAllById(permissionIds);
            if (permissions.size() != permissionIds.size()) {
                throw new IllegalArgumentException(msg("msg.permission.not.found"));
            }
            Set<RolePermission> rolePermissions = permissions.stream()
                    .map(p -> RolePermission.builder().role(role).permission(p).build())
                    .collect(Collectors.toSet());
            role.setRolePermissions(rolePermissions);
        }

        Role saved = roleRepository.save(role);
        auditRoleChange(AuditEventCategory.ROLE_CREATED, saved);

        if (permissionIds != null && !permissionIds.isEmpty()) {
            eventBus.publish(new RolePermissionsChangedEvent(saved.getId()));
        }

        return saved;
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithAuthorities", allEntries = true),
                    @CacheEvict(value = "roles", allEntries = true),
                    @CacheEvict(value = "rolesWithoutExpression", allEntries = true)
            },
            put = {@CachePut(value = "roles", key = "#result.id")}
    )
    public Role updateRole(Role role, List<Long> permissionIds) {
        Role existingRole = roleRepository.findByIdWithPermissions(role.getId())
                .orElseThrow(() -> new IllegalArgumentException("Role not found with ID: " + role.getId()));

        existingRole.setRoleName(role.getRoleName());
        existingRole.setRoleDesc(role.getRoleDesc());
        existingRole.setExpression(role.isExpression());

        Set<Long> desiredPermissionIds = permissionIds != null ? new HashSet<>(permissionIds) : new HashSet<>();
        Set<RolePermission> currentRolePermissions = existingRole.getRolePermissions();

        currentRolePermissions.removeIf(rp -> !desiredPermissionIds.contains(rp.getPermission().getId()));

        Set<Long> currentPermissionIds = currentRolePermissions.stream()
                .map(rp -> rp.getPermission().getId())
                .collect(Collectors.toSet());

        Set<Long> newPermIds = desiredPermissionIds.stream()
                .filter(desiredId -> !currentPermissionIds.contains(desiredId))
                .collect(Collectors.toSet());
        if (!newPermIds.isEmpty()) {
            permissionRepository.findAllById(newPermIds).forEach(permission ->
                    currentRolePermissions.add(RolePermission.builder().role(existingRole).permission(permission).build()));
        }

        Role savedRole = roleRepository.save(existingRole);
        eventBus.publish(new RolePermissionsChangedEvent(savedRole.getId()));
        auditRoleChange(AuditEventCategory.ROLE_UPDATED, savedRole);

        return savedRole;
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithAuthorities", allEntries = true),
                    @CacheEvict(value = "roles", allEntries = true),
                    @CacheEvict(value = "rolesWithoutExpression", allEntries = true),
                    @CacheEvict(value = "roles", key = "#id")
            }
    )
    public void deleteRole(long id) {
        // Check if role is referenced in any active hierarchy (exact token matching)
        Role role = roleRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Role not found with ID: " + id));
        List<String> referencedIn = new ArrayList<>();
        roleHierarchyRepository.findAllByIsActiveTrue().forEach(hierarchy -> {
            String hs = hierarchy.getHierarchyString();
            if (hs != null) {
                String normalized = hs.replace("\\n", "\n");
                boolean referenced = Arrays.stream(normalized.split("[\\r\\n]+"))
                        .flatMap(line -> Arrays.stream(line.split("\\s*>\\s*")))
                        .map(String::trim)
                        .anyMatch(token -> token.equals(role.getRoleName()));
                if (referenced) {
                    referencedIn.add(hierarchy.getDescription() != null ? hierarchy.getDescription() : "ID:" + hierarchy.getId());
                }
            }
        });
        if (!referencedIn.isEmpty()) {
            throw new IllegalStateException(msg("msg.role.delete.referenced",
                    role.getRoleName(), String.join(", ", referencedIn)));
        }
        policySynchronizationService.cleanupAutoPolicy(role.getRoleName());
        auditRoleChange(AuditEventCategory.ROLE_DELETED, role);
        roleRepository.deleteById(id);
    }

    private void auditRoleChange(AuditEventCategory category, Role role) {
        try {
            String principal = "SYSTEM";
            var auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getName() != null) principal = auth.getName();

            centralAuditFacade.recordAsync(AuditRecord.builder()
                    .eventCategory(category)
                    .principalName(principal)
                    .resourceIdentifier(role.getRoleName() != null ? role.getRoleName() : "")
                    .eventSource("IAM")
                    .action(category.name())
                    .decision("SUCCESS")
                    .outcome("SUCCESS")
                    .details(Map.of(
                            "roleId", role.getId() != null ? role.getId() : 0L,
                            "roleName", role.getRoleName() != null ? role.getRoleName() : ""))
                    .build());
        } catch (Exception e) {
            log.error("Failed to audit role change: {}", role.getRoleName(), e);
        }
    }
}
