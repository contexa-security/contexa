package io.contexa.contexaiam.admin.web.auth.service.impl;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.enums.AuditEventCategory;
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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final IntegrationEventBus eventBus;
    private final CentralAuditFacade centralAuditFacade;

    @Transactional(readOnly = true)
    @Cacheable(value = "roles", key = "#id")
    public Role getRole(long id) {
        return roleRepository.findByIdWithPermissions(id)
                .orElseThrow(() -> new IllegalArgumentException("Role not found with ID: " + id));
    }

    @Transactional(readOnly = true)
    @Cacheable(value = "roles", key = "'allRoles'")
    public List<Role> getRoles() {
        return roleRepository.findAllWithPermissions();
    }

    @Transactional(readOnly = true)
    @Cacheable(value = "rolesWithoutExpression", key = "'allRolesWithoutExpression'")
    public List<Role> getRolesWithoutExpression() {
        return roleRepository.findAllRolesWithoutExpression();
    }

    @Override
    @Transactional(readOnly = true)
    public Page<Role> searchRoles(String keyword, Pageable pageable) {
        return roleRepository.searchByKeyword(keyword, pageable);
    }

    @Transactional
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithAuthorities", allEntries = true),
                    @CacheEvict(value = "roles", allEntries = true),
                    @CacheEvict(value = "rolesWithoutExpression", allEntries = true)
            },
            put = {@CachePut(value = "roles", key = "#result.id")}
    )
    @Protectable
    public Role createRole(Role role, List<Long> permissionIds) {
        if (roleRepository.findByRoleName(role.getRoleName()).isPresent()) {
            throw new IllegalArgumentException("Role with name " + role.getRoleName() + " already exists.");
        }

        if (permissionIds != null && !permissionIds.isEmpty()) {
            Set<RolePermission> rolePermissions = new HashSet<>();
            for (Long permId : permissionIds) {
                Permission permission = permissionRepository.findById(permId)
                        .orElseThrow(() -> new IllegalArgumentException("Permission not found with ID: " + permId));
                rolePermissions.add(RolePermission.builder().role(role).permission(permission).build());
            }
            role.setRolePermissions(rolePermissions);
        }

        Role saved = roleRepository.save(role);
        auditRoleChange(AuditEventCategory.ROLE_CREATED, saved);
        return saved;
    }

    @Transactional
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithAuthorities", allEntries = true),
                    @CacheEvict(value = "roles", allEntries = true),
                    @CacheEvict(value = "rolesWithoutExpression", allEntries = true)
            },
            put = {@CachePut(value = "roles", key = "#result.id")}
    )
    @Protectable
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

        desiredPermissionIds.stream()
                .filter(desiredId -> !currentPermissionIds.contains(desiredId))
                .forEach(newPermId -> {
                    Permission permission = permissionRepository.findById(newPermId)
                            .orElseThrow(() -> new IllegalArgumentException("Permission not found with ID: " + newPermId));
                    currentRolePermissions.add(RolePermission.builder().role(existingRole).permission(permission).build());
                });

        Role savedRole = roleRepository.save(existingRole);
        eventBus.publish(new RolePermissionsChangedEvent(savedRole.getId()));
        auditRoleChange(AuditEventCategory.ROLE_UPDATED, savedRole);

        return savedRole;
    }

    @Transactional
    @Caching(
            evict = {
                    @CacheEvict(value = "usersWithAuthorities", allEntries = true),
                    @CacheEvict(value = "roles", allEntries = true),
                    @CacheEvict(value = "rolesWithoutExpression", allEntries = true),
                    @CacheEvict(value = "roles", key = "#id")
            }
    )
    @Protectable
    public void deleteRole(long id) {
        roleRepository.findById(id).ifPresent(role -> auditRoleChange(AuditEventCategory.ROLE_DELETED, role));
        roleRepository.deleteById(id);
    }

    private void auditRoleChange(AuditEventCategory category, Role role) {
        try {
            String principal = "SYSTEM";
            var auth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getName() != null) principal = auth.getName();

            centralAuditFacade.recordAsync(AuditRecord.builder()
                    .eventCategory(category)
                    .principalName(principal)
                    .resourceIdentifier(role.getRoleName() != null ? role.getRoleName() : "")
                    .eventSource("IAM")
                    .action(category.name())
                    .decision("SUCCESS")
                    .outcome("SUCCESS")
                    .details(java.util.Map.of(
                            "roleId", role.getId() != null ? role.getId() : 0L,
                            "roleName", role.getRoleName() != null ? role.getRoleName() : ""))
                    .build());
        } catch (Exception e) {
            log.error("Failed to audit role change: {}", role.getRoleName(), e);
        }
    }
}