package io.contexa.contexacommon.security.authority;

import io.contexa.contexacommon.entity.*;
import io.contexa.contexacommon.repository.GroupRolePermissionRepository;
import io.contexa.contexacommon.repository.UserRolePermissionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.GrantedAuthority;

import java.util.*;

/**
 * Central authority resolver that builds the complete set of granted authorities
 * for a user, respecting CRUD permission selections per user-role and group-role.
 */
@Slf4j
@RequiredArgsConstructor
public class AuthorityResolver {

    private final UserRolePermissionRepository userRolePermissionRepository;
    private final GroupRolePermissionRepository groupRolePermissionRepository;
    private final RoleHierarchy roleHierarchy;

    /**
     * Resolve all authorities for a user:
     * 1. Direct roles -> UserRolePermission (selected CRUDs only)
     * 2. Group-inherited roles -> GroupRolePermission (selected CRUDs only)
     * 3. Role hierarchy expansion (inherited roles get full CRUDs from RolePermission)
     */
    public Set<GrantedAuthority> resolveAuthorities(Users user) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        // 1. Direct role assignments -> user-specific CRUD permissions
        Optional.ofNullable(user.getUserRoles())
                .orElse(Collections.emptySet()).stream()
                .map(UserRole::getRole)
                .filter(Objects::nonNull)
                .filter(Role::isEnabled)
                .forEach(role -> {
                    authorities.add(new RoleAuthority(role));
                    List<UserRolePermission> urps = userRolePermissionRepository
                            .findByUserIdAndRoleId(user.getId(), role.getId());
                    if (!urps.isEmpty()) {
                        urps.forEach(urp -> authorities.add(new PermissionAuthority(urp.getPermission())));
                    } else {
                        // Fallback: if no UserRolePermission entries exist, grant all role permissions
                        // This ensures backward compatibility during migration
                        Optional.ofNullable(role.getRolePermissions())
                                .orElse(Collections.emptySet()).stream()
                                .map(RolePermission::getPermission)
                                .filter(Objects::nonNull)
                                .forEach(p -> authorities.add(new PermissionAuthority(p)));
                    }
                });

        // 2. Group-inherited role assignments -> group-specific CRUD permissions
        Optional.ofNullable(user.getUserGroups())
                .orElse(Collections.emptySet()).stream()
                .map(UserGroup::getGroup)
                .filter(Objects::nonNull)
                .forEach(group -> {
                    Optional.ofNullable(group.getGroupRoles())
                            .orElse(Collections.emptySet()).stream()
                            .map(GroupRole::getRole)
                            .filter(Objects::nonNull)
                            .filter(Role::isEnabled)
                            .forEach(role -> {
                                authorities.add(new RoleAuthority(role));
                                List<GroupRolePermission> grps = groupRolePermissionRepository
                                        .findByGroupIdAndRoleId(group.getId(), role.getId());
                                if (!grps.isEmpty()) {
                                    grps.forEach(grp -> authorities.add(new PermissionAuthority(grp.getPermission())));
                                } else {
                                    // Fallback: backward compatibility
                                    Optional.ofNullable(role.getRolePermissions())
                                            .orElse(Collections.emptySet()).stream()
                                            .map(RolePermission::getPermission)
                                            .filter(Objects::nonNull)
                                            .forEach(p -> authorities.add(new PermissionAuthority(p)));
                                }
                            });
                });

        // 3. Role hierarchy expansion
        // Inherited roles (via hierarchy) get full CRUDs from RolePermission
        // RoleHierarchy.getReachableGrantedAuthorities only expands RoleAuthority,
        // PermissionAuthority passes through unchanged
        Collection<? extends GrantedAuthority> expanded = roleHierarchy.getReachableGrantedAuthorities(authorities);

        return new HashSet<>(expanded);
    }
}
