package io.contexa.contexaiam.admin.web.auth.service.impl;

import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.common.event.dto.RolePermissionsChangedEvent;
import io.contexa.contexaiam.common.event.service.IntegrationEventBus;
import io.contexa.contexaiam.security.xacml.pap.service.PolicySynchronizationService;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.RolePermission;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
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
    private final PolicySynchronizationService policySyncService;
    private final CustomDynamicAuthorizationManager authorizationManager;
    private final IntegrationEventBus eventBus;

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

    @Transactional
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

        return roleRepository.save(role);
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
    public Role updateRole(Role role, List<Long> permissionIds) {
        Role existingRole = roleRepository.findByIdWithPermissions(role.getId())
                .orElseThrow(() -> new IllegalArgumentException("Role not found with ID: " + role.getId()));

        existingRole.setRoleName(role.getRoleName());
        existingRole.setRoleDesc(role.getRoleDesc());
        existingRole.setIsExpression(role.getIsExpression());

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
    public void deleteRole(long id) {
        roleRepository.deleteById(id);
    }
}