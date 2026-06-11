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
package io.contexa.contexacommon.security.authority;

import io.contexa.contexacommon.entity.*;
import io.contexa.contexacommon.repository.GroupRolePermissionRepository;
import io.contexa.contexacommon.repository.RolePermissionRepository;
import io.contexa.contexacommon.repository.UserRolePermissionRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.GrantedAuthority;

import java.util.*;

/**
 * Central authority resolver that builds the complete set of granted authorities
 * for a user, respecting CRUD permission selections per user-role and group-role.
 */
@Slf4j
public class AuthorityResolver {

    private final UserRolePermissionRepository userRolePermissionRepository;
    private final GroupRolePermissionRepository groupRolePermissionRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final RoleHierarchy roleHierarchy;

    public AuthorityResolver(UserRolePermissionRepository userRolePermissionRepository,
                             GroupRolePermissionRepository groupRolePermissionRepository,
                             RoleHierarchy roleHierarchy) {
        this(userRolePermissionRepository, groupRolePermissionRepository, null, roleHierarchy);
    }

    public AuthorityResolver(UserRolePermissionRepository userRolePermissionRepository,
                             GroupRolePermissionRepository groupRolePermissionRepository,
                             RolePermissionRepository rolePermissionRepository,
                             RoleHierarchy roleHierarchy) {
        this.userRolePermissionRepository = userRolePermissionRepository;
        this.groupRolePermissionRepository = groupRolePermissionRepository;
        this.rolePermissionRepository = rolePermissionRepository;
        this.roleHierarchy = roleHierarchy;
    }

    /**
     * Resolve all authorities for a user:
     * 1. Direct roles -> UserRolePermission (selected CRUDs only)
     * 2. Group-inherited roles -> GroupRolePermission (selected CRUDs only)
     * 3. Role hierarchy expansion (inherited roles get full CRUDs from RolePermission)
     */
    public Set<GrantedAuthority> resolveAuthorities(Users user) {
        Set<GrantedAuthority> authorities = new HashSet<>();
        Map<Long, List<UserRolePermission>> userPermissionsByRole = loadUserPermissionsByRole(user);
        Map<Long, Map<Long, List<GroupRolePermission>>> groupPermissionsByGroupAndRole =
                loadGroupPermissionsByGroupAndRole(user);
        Map<Long, List<RolePermission>> rolePermissionsByRole = loadRolePermissionsByRole(user);

        Optional.ofNullable(user.getUserRoles())
                .orElse(Collections.emptySet()).stream()
                .map(UserRole::getRole)
                .filter(Objects::nonNull)
                .filter(Role::isEnabled)
                .forEach(role -> {
                    authorities.add(new RoleAuthority(role));
                    List<UserRolePermission> urps = userPermissionsByRole.getOrDefault(role.getId(), Collections.emptyList());
                    if (!urps.isEmpty()) {
                        urps.forEach(urp -> authorities.add(new PermissionAuthority(urp.getPermission())));
                    } else {
                        rolePermissionsByRole.getOrDefault(role.getId(), Collections.emptyList()).stream()
                                .map(RolePermission::getPermission)
                                .filter(Objects::nonNull)
                                .forEach(p -> authorities.add(new PermissionAuthority(p)));
                    }
                });

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
                                List<GroupRolePermission> grps = groupPermissionsByGroupAndRole
                                        .getOrDefault(group.getId(), Collections.emptyMap())
                                        .getOrDefault(role.getId(), Collections.emptyList());
                                if (!grps.isEmpty()) {
                                    grps.forEach(grp -> authorities.add(new PermissionAuthority(grp.getPermission())));
                                } else {
                                    rolePermissionsByRole.getOrDefault(role.getId(), Collections.emptyList()).stream()
                                            .map(RolePermission::getPermission)
                                            .filter(Objects::nonNull)
                                            .forEach(p -> authorities.add(new PermissionAuthority(p)));
                                }
                            });
                });

        Collection<? extends GrantedAuthority> expanded = roleHierarchy.getReachableGrantedAuthorities(authorities);

        return new HashSet<>(expanded);
    }

    private Map<Long, List<UserRolePermission>> loadUserPermissionsByRole(Users user) {
        if (user == null || user.getId() == null) {
            return Collections.emptyMap();
        }
        List<UserRolePermission> permissions = userRolePermissionRepository.findByUserId(user.getId());
        Map<Long, List<UserRolePermission>> byRole = new HashMap<>();
        for (UserRolePermission permission : permissions) {
            Long roleId = permission.getRole() != null ? permission.getRole().getId() : null;
            if (roleId != null) {
                byRole.computeIfAbsent(roleId, ignored -> new ArrayList<>()).add(permission);
            }
        }
        return byRole;
    }

    private Map<Long, Map<Long, List<GroupRolePermission>>> loadGroupPermissionsByGroupAndRole(Users user) {
        if (user == null) {
            return Collections.emptyMap();
        }
        Set<Long> groupIds = new HashSet<>();
        Optional.ofNullable(user.getUserGroups())
                .orElse(Collections.emptySet()).stream()
                .map(UserGroup::getGroup)
                .filter(Objects::nonNull)
                .map(Group::getId)
                .filter(Objects::nonNull)
                .forEach(groupIds::add);

        if (groupIds.isEmpty()) {
            return Collections.emptyMap();
        }

        List<GroupRolePermission> permissions = groupRolePermissionRepository.findByGroupIds(groupIds);
        Map<Long, Map<Long, List<GroupRolePermission>>> byGroupAndRole = new HashMap<>();
        for (GroupRolePermission permission : permissions) {
            Long groupId = permission.getGroup() != null ? permission.getGroup().getId() : null;
            Long roleId = permission.getRole() != null ? permission.getRole().getId() : null;
            if (groupId != null && roleId != null) {
                byGroupAndRole
                        .computeIfAbsent(groupId, ignored -> new HashMap<>())
                        .computeIfAbsent(roleId, ignored -> new ArrayList<>())
                        .add(permission);
            }
        }
        return byGroupAndRole;
    }

    private Map<Long, List<RolePermission>> loadRolePermissionsByRole(Users user) {
        Set<Long> roleIds = collectRoleIds(user);
        if (roleIds.isEmpty()) {
            return Collections.emptyMap();
        }

        List<RolePermission> permissions = rolePermissionRepository != null
                ? rolePermissionRepository.findByRoleIds(roleIds)
                : collectLoadedRolePermissions(user);
        Map<Long, List<RolePermission>> byRole = new HashMap<>();
        for (RolePermission permission : permissions) {
            Long roleId = permission.getRole() != null ? permission.getRole().getId() : null;
            if (roleId != null) {
                byRole.computeIfAbsent(roleId, ignored -> new ArrayList<>()).add(permission);
            }
        }
        return byRole;
    }

    private List<RolePermission> collectLoadedRolePermissions(Users user) {
        if (user == null) {
            return Collections.emptyList();
        }
        List<RolePermission> permissions = new ArrayList<>();
        Optional.ofNullable(user.getUserRoles())
                .orElse(Collections.emptySet()).stream()
                .map(UserRole::getRole)
                .filter(Objects::nonNull)
                .forEach(role -> permissions.addAll(Optional.ofNullable(role.getRolePermissions())
                        .orElse(Collections.emptySet())));

        Optional.ofNullable(user.getUserGroups())
                .orElse(Collections.emptySet()).stream()
                .map(UserGroup::getGroup)
                .filter(Objects::nonNull)
                .flatMap(group -> Optional.ofNullable(group.getGroupRoles())
                        .orElse(Collections.emptySet()).stream())
                .map(GroupRole::getRole)
                .filter(Objects::nonNull)
                .forEach(role -> permissions.addAll(Optional.ofNullable(role.getRolePermissions())
                        .orElse(Collections.emptySet())));
        return permissions;
    }

    private Set<Long> collectRoleIds(Users user) {
        Set<Long> roleIds = new HashSet<>();
        if (user == null) {
            return roleIds;
        }

        Optional.ofNullable(user.getUserRoles())
                .orElse(Collections.emptySet()).stream()
                .map(UserRole::getRole)
                .filter(Objects::nonNull)
                .map(Role::getId)
                .filter(Objects::nonNull)
                .forEach(roleIds::add);

        Optional.ofNullable(user.getUserGroups())
                .orElse(Collections.emptySet()).stream()
                .map(UserGroup::getGroup)
                .filter(Objects::nonNull)
                .flatMap(group -> Optional.ofNullable(group.getGroupRoles())
                        .orElse(Collections.emptySet()).stream())
                .map(GroupRole::getRole)
                .filter(Objects::nonNull)
                .map(Role::getId)
                .filter(Objects::nonNull)
                .forEach(roleIds::add);

        return roleIds;
    }
}
