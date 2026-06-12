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

import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.GroupRole;
import io.contexa.contexacommon.entity.GroupRolePermission;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.UserGroup;
import io.contexa.contexacommon.entity.UserRole;
import io.contexa.contexacommon.entity.UserRolePermission;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.GroupRolePermissionRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.repository.UserRolePermissionRepository;
import io.contexa.contexacommon.repository.UserRoleRepository;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessActionResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessCenterStats;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessGroupDetailResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessGroupReferenceResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessGroupRoleSourceResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessGroupSummaryResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessPageResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessPermissionSourceResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessPermissionSummaryResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessRoleAssignmentsRequest;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessRoleDetailResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessRoleListResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessRoleOptionResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessRoleSourceResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessRoleSummaryResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessUserDetailResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessUserMemberResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.AccessUserSummaryResponse;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.UpdateRolePermissionsRequest;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.UpdateUserGroupsRequest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;

@RequiredArgsConstructor
@Slf4j
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
public class AccessCenterService {

    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final GroupRepository groupRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final RoleService roleService;
    private final UserRolePermissionRepository userRolePermissionRepository;
    private final GroupRolePermissionRepository groupRolePermissionRepository;

    public AccessCenterStats getStats() {
        return new AccessCenterStats(
                userRepository.count(),
                groupRepository.count(),
                roleRepository.count(),
                permissionRepository.count()
        );
    }

    public AccessPageResponse<AccessUserSummaryResponse> searchUsers(String keyword, Pageable pageable) {
        Page<Users> page;
        if (keyword != null && !keyword.isBlank()) {
            page = userRepository.findByUsernameContainingIgnoreCaseOrNameContainingIgnoreCase(
                    keyword, keyword, pageable);
        } else {
            page = userRepository.findAll(pageable);
        }

        List<AccessUserSummaryResponse> content = page.getContent().stream()
                .map(u -> new AccessUserSummaryResponse(
                        u.getId(),
                        u.getUsername(),
                        u.getName(),
                        u.getEmail(),
                        u.isEnabled(),
                        u.getDepartment()
                ))
                .toList();

        return new AccessPageResponse<>(content, page.getTotalElements(), page.getTotalPages());
    }

    public AccessUserDetailResponse getUserDetail(Long userId) {
        log.error("[AccessCenterController] findByIdWithGroupsRolesAndPermissions userId={}", userId);
        Users user = userRepository.findByIdWithGroupsRolesAndPermissions(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + userId));

        List<AccessGroupReferenceResponse> groups = user.getUserGroups().stream()
                .map(ug -> new AccessGroupReferenceResponse(
                        ug.getGroup().getId(),
                        ug.getGroup().getName()
                ))
                .toList();

        List<AccessRoleSourceResponse> directRoles = user.getUserRoles().stream()
                .map(ur -> new AccessRoleSourceResponse(
                        ur.getRole().getId(),
                        ur.getRole().getRoleName(),
                        ur.getRole().getRoleDesc(),
                        "direct"
                ))
                .toList();

        List<AccessGroupRoleSourceResponse> groupRoles = user.getUserGroups().stream()
                .flatMap(ug -> ug.getGroup().getGroupRoles().stream()
                        .map(gr -> new AccessGroupRoleSourceResponse(
                                gr.getRole().getId(),
                                gr.getRole().getRoleName(),
                                gr.getRole().getRoleDesc(),
                                "group",
                                ug.getGroup().getName()
                        )))
                .toList();

        Set<Long> allRoleIds = new HashSet<>();
        user.getUserRoles().forEach(ur -> allRoleIds.add(ur.getRole().getId()));
        user.getUserGroups().forEach(ug ->
                ug.getGroup().getGroupRoles().forEach(gr -> allRoleIds.add(gr.getRole().getId())));

        Set<String> seenPermNames = new HashSet<>();
        List<AccessPermissionSourceResponse> permissions = new ArrayList<>();
        user.getUserRoles().stream()
                .flatMap(ur -> ur.getRole().getRolePermissions().stream())
                .forEach(rp -> {
                    if (seenPermNames.add(rp.getPermission().getName())) {
                        permissions.add(new AccessPermissionSourceResponse(
                                rp.getPermission().getName(),
                                rp.getPermission().getFriendlyName(),
                                "direct"
                        ));
                    }
                });
        user.getUserGroups().stream()
                .flatMap(ug -> ug.getGroup().getGroupRoles().stream())
                .flatMap(gr -> gr.getRole().getRolePermissions().stream())
                .forEach(rp -> {
                    if (seenPermNames.add(rp.getPermission().getName())) {
                        permissions.add(new AccessPermissionSourceResponse(
                                rp.getPermission().getName(),
                                rp.getPermission().getFriendlyName(),
                                "group"
                        ));
                    }
                });

        return new AccessUserDetailResponse(
                user.getId(),
                user.getUsername(),
                user.getName(),
                user.getEmail(),
                user.getDepartment(),
                user.isEnabled(),
                groups,
                directRoles,
                groupRoles,
                permissions
        );
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public AccessActionResponse updateUserGroups(Long userId, UpdateUserGroupsRequest request) {
        List<Long> groupIds = request.groupIdsOrEmpty();
        Users user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + userId));

        user.getUserGroups().clear();
        groupIds.forEach(gid -> {
            Group group = groupRepository.findById(gid)
                    .orElseThrow(() -> new IllegalArgumentException("Group not found: " + gid));
            user.getUserGroups().add(UserGroup.builder().user(user).group(group).build());
        });
        userRepository.save(user);

        return new AccessActionResponse(true, "Groups updated successfully.");
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public AccessActionResponse updateUserDirectRoles(Long userId, AccessRoleAssignmentsRequest request) {
        Users user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + userId));
        String principal = extractCurrentUsername();

        user.getUserRoles().clear();
        userRolePermissionRepository.deleteByUserId(userId);
        userRolePermissionRepository.flush();

        if (request.getRoleAssignments() != null) {
            for (var assignment : request.getRoleAssignments()) {
                Long roleId = assignment.getRoleId();
                List<String> cruds = assignment.crudPermissionsOrDefault();
                List<Long> extraPermIds = assignment.extraPermissionIdsOrEmpty();

                Role role = roleRepository.findById(roleId)
                        .orElseThrow(() -> new IllegalArgumentException("Role not found: " + roleId));
                user.getUserRoles().add(UserRole.builder().user(user).role(role).build());

                Set<String> crudSet = new HashSet<>(cruds);
                crudSet.add("READ");

                for (String crud : crudSet) {
                    Permission perm = permissionRepository.findByName(crud).orElse(null);
                    if (perm != null) {
                        UserRolePermission urp = new UserRolePermission();
                        urp.setUser(user);
                        urp.setRole(role);
                        urp.setPermission(perm);
                        urp.setAssignedBy(principal);
                        userRolePermissionRepository.save(urp);
                    }
                }

                for (Long permId : extraPermIds) {
                    Permission perm = permissionRepository.findById(permId).orElse(null);
                    if (perm != null) {
                        UserRolePermission urp = new UserRolePermission();
                        urp.setUser(user);
                        urp.setRole(role);
                        urp.setPermission(perm);
                        urp.setAssignedBy(principal);
                        userRolePermissionRepository.save(urp);
                    }
                }
            }
        } else {
            for (Long roleId : request.roleIdsOrEmpty()) {
                Role role = roleRepository.findById(roleId)
                        .orElseThrow(() -> new IllegalArgumentException("Role not found: " + roleId));
                user.getUserRoles().add(UserRole.builder().user(user).role(role).build());

                role.getRolePermissions().forEach(rp -> {
                    Permission perm = rp.getPermission();
                    if (isCrudPermission(perm)) {
                        UserRolePermission urp = new UserRolePermission();
                        urp.setUser(user);
                        urp.setRole(role);
                        urp.setPermission(perm);
                        urp.setAssignedBy(principal);
                        userRolePermissionRepository.save(urp);
                    }
                });
            }
        }

        userRepository.save(user);
        return new AccessActionResponse(true, "Direct roles updated successfully.");
    }

    public List<AccessGroupSummaryResponse> getAllGroups() {
        return groupRepository.findAll().stream()
                .map(g -> new AccessGroupSummaryResponse(g.getId(), g.getName(), g.getDescription()))
                .toList();
    }

    public AccessGroupDetailResponse getGroupDetail(Long groupId) {
        Group group = groupRepository.findById(groupId)
                .orElseThrow(() -> new IllegalArgumentException("Group not found: " + groupId));

        List<AccessRoleSummaryResponse> roles = group.getGroupRoles().stream()
                .map(gr -> new AccessRoleSummaryResponse(
                        gr.getRole().getId(),
                        gr.getRole().getRoleName(),
                        gr.getRole().getRoleDesc()
                ))
                .toList();

        List<AccessUserMemberResponse> members = userRepository.findAll().stream()
                .filter(u -> u.getUserGroups().stream().anyMatch(ug -> ug.getGroup().getId().equals(groupId)))
                .map(u -> new AccessUserMemberResponse(u.getId(), u.getUsername(), u.getName()))
                .toList();

        return new AccessGroupDetailResponse(
                group.getId(),
                group.getName(),
                group.getDescription(),
                roles,
                members
        );
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public AccessActionResponse updateGroupRoles(Long groupId, AccessRoleAssignmentsRequest request) {
        Group group = groupRepository.findById(groupId)
                .orElseThrow(() -> new IllegalArgumentException("Group not found: " + groupId));
        String principal = extractCurrentUsername();

        group.getGroupRoles().clear();
        groupRolePermissionRepository.deleteByGroupId(groupId);
        groupRolePermissionRepository.flush();

        if (request.getRoleAssignments() != null) {
            for (var assignment : request.getRoleAssignments()) {
                Long roleId = assignment.getRoleId();
                List<String> cruds = assignment.crudPermissionsOrDefault();
                List<Long> extraPermIds = assignment.extraPermissionIdsOrEmpty();

                Role role = roleRepository.findById(roleId)
                        .orElseThrow(() -> new IllegalArgumentException("Role not found: " + roleId));
                group.getGroupRoles().add(GroupRole.builder().group(group).role(role).build());

                Set<String> crudSet = new HashSet<>(cruds);
                crudSet.add("READ");

                for (String crud : crudSet) {
                    Permission perm = permissionRepository.findByName(crud).orElse(null);
                    if (perm != null) {
                        GroupRolePermission grp = new GroupRolePermission();
                        grp.setGroup(group);
                        grp.setRole(role);
                        grp.setPermission(perm);
                        grp.setAssignedBy(principal);
                        groupRolePermissionRepository.save(grp);
                    }
                }

                for (Long permId : extraPermIds) {
                    Permission perm = permissionRepository.findById(permId).orElse(null);
                    if (perm != null) {
                        GroupRolePermission grp = new GroupRolePermission();
                        grp.setGroup(group);
                        grp.setRole(role);
                        grp.setPermission(perm);
                        grp.setAssignedBy(principal);
                        groupRolePermissionRepository.save(grp);
                    }
                }
            }
        } else {
            for (Long roleId : request.roleIdsOrEmpty()) {
                Role role = roleRepository.findById(roleId)
                        .orElseThrow(() -> new IllegalArgumentException("Role not found: " + roleId));
                group.getGroupRoles().add(GroupRole.builder().group(group).role(role).build());

                role.getRolePermissions().forEach(rp -> {
                    Permission perm = rp.getPermission();
                    if (isCrudPermission(perm)) {
                        GroupRolePermission grpPerm = new GroupRolePermission();
                        grpPerm.setGroup(group);
                        grpPerm.setRole(role);
                        grpPerm.setPermission(perm);
                        grpPerm.setAssignedBy(principal);
                        groupRolePermissionRepository.save(grpPerm);
                    }
                });
            }
        }

        groupRepository.save(group);
        return new AccessActionResponse(true, "Group roles updated successfully.");
    }

    public List<AccessRoleListResponse> getAllRoles() {
        return roleRepository.findAllWithPermissions().stream()
                .map(r -> new AccessRoleListResponse(
                        r.getId(),
                        r.getRoleName(),
                        r.getRoleDesc(),
                        r.getRolePermissions() != null ? r.getRolePermissions().size() : 0
                ))
                .toList();
    }

    public AccessRoleDetailResponse getRoleDetail(Long roleId) {
        Role role = roleService.getRole(roleId);

        List<AccessPermissionSummaryResponse> permissions = role.getRolePermissions().stream()
                .map(rp -> new AccessPermissionSummaryResponse(
                        rp.getPermission().getId(),
                        rp.getPermission().getName(),
                        rp.getPermission().getFriendlyName(),
                        rp.getPermission().getDescription()
                ))
                .toList();

        List<AccessUserMemberResponse> directUsers = userRoleRepository.findByRoleIdWithUser(roleId).stream()
                .map(ur -> new AccessUserMemberResponse(
                        ur.getUser().getId(),
                        ur.getUser().getUsername(),
                        ur.getUser().getName()
                ))
                .toList();

        return new AccessRoleDetailResponse(
                role.getId(),
                role.getRoleName(),
                role.getRoleDesc(),
                permissions,
                directUsers
        );
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public AccessActionResponse updateRolePermissions(Long roleId, UpdateRolePermissionsRequest request) {
        Role role = roleService.getRole(roleId);
        roleService.updateRole(role, request.permissionIdsOrEmpty());
        return new AccessActionResponse(true, "Role permissions updated successfully.");
    }

    private static final Set<String> CRUD_PERMISSION_NAMES =
            Set.of("READ", "WRITE", "UPDATE", "DELETE");

    private static boolean isCrudPermission(Permission p) {
        return p != null && p.getName() != null && CRUD_PERMISSION_NAMES.contains(p.getName());
    }

    public List<AccessRoleOptionResponse> getAllRolesSimple() {
        return roleRepository.findAllWithPermissions().stream()
                .map(r -> {
                    List<Permission> mapped = r.getRolePermissions() != null
                            ? r.getRolePermissions().stream()
                                    .map(rp -> rp.getPermission())
                                    .filter(Objects::nonNull)
                                    .toList()
                            : List.of();
                    // Classification is name-based (not target_type-based) so admins can
                    // create non-CRUD permissions with any target_type without breaking the UI
                    List<String> cruds = mapped.stream()
                            .filter(AccessCenterService::isCrudPermission)
                            .map(Permission::getName)
                            .toList();
                    List<AccessPermissionSummaryResponse> extras = mapped.stream()
                            .filter(p -> !isCrudPermission(p))
                            .map(p -> new AccessPermissionSummaryResponse(
                                    p.getId(),
                                    p.getName(),
                                    p.getFriendlyName(),
                                    p.getDescription()))
                            .toList();
                    // Return only the CRUDs actually mapped to this role.
                    // Empty list means "no CRUD mapped" — JS shows all 4 chips but only READ default-checked.
                    return new AccessRoleOptionResponse(
                            r.getId(),
                            r.getRoleName(),
                            r.getRoleDesc(),
                            cruds,
                            extras
                    );
                })
                .toList();
    }

    public List<AccessPermissionSummaryResponse> getAllPermissions() {
        return permissionRepository.findAll().stream()
                .map(p -> new AccessPermissionSummaryResponse(
                        p.getId(),
                        p.getName(),
                        p.getFriendlyName(),
                        p.getDescription()
                ))
                .toList();
    }

    public List<String> getUserRoleCruds(Long userId, Long roleId) {
        return userRolePermissionRepository.findByUserIdAndRoleId(userId, roleId)
                .stream().map(urp -> urp.getPermission().getName()).toList();
    }

    public List<String> getGroupRoleCruds(Long groupId, Long roleId) {
        return groupRolePermissionRepository.findByGroupIdAndRoleId(groupId, roleId)
                .stream().map(grp -> grp.getPermission().getName()).toList();
    }

    private String extractCurrentUsername() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null ? auth.getName() : "SYSTEM";
    }
}
