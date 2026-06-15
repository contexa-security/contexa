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

import io.contexa.contexacommon.entity.*;
import io.contexa.contexacommon.repository.*;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.center.dto.AccessCenterDtos.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AccessCenterService")
class AccessCenterServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private UserRoleRepository userRoleRepository;
    @Mock private GroupRepository groupRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private PermissionRepository permissionRepository;
    @Mock private RoleService roleService;
    @Mock private UserRolePermissionRepository userRolePermissionRepository;
    @Mock private GroupRolePermissionRepository groupRolePermissionRepository;

    @InjectMocks
    private AccessCenterService service;

    @BeforeEach
    void setUpSecurity() {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("admin", "password"));
    }

    @Nested
    @DisplayName("getStats")
    class GetStats {
        @Test
        @DisplayName("should aggregate repository counts")
        void success() {
            when(userRepository.count()).thenReturn(10L);
            when(groupRepository.count()).thenReturn(5L);
            when(roleRepository.count()).thenReturn(4L);
            when(permissionRepository.count()).thenReturn(20L);

            AccessCenterStats stats = service.getStats();

            assertThat(stats.userCount()).isEqualTo(10L);
            assertThat(stats.groupCount()).isEqualTo(5L);
            assertThat(stats.roleCount()).isEqualTo(4L);
            assertThat(stats.permissionCount()).isEqualTo(20L);
        }
    }

    @Nested
    @DisplayName("searchUsers")
    class SearchUsers {
        @Test
        @DisplayName("should find all users when keyword is empty")
        void emptyKeyword() {
            PageRequest pageable = PageRequest.of(0, 10);
            Users user = Users.builder().id(1L).username("alice").build();
            when(userRepository.findAll(pageable)).thenReturn(new PageImpl<>(List.of(user)));

            AccessPageResponse<AccessUserSummaryResponse> response = service.searchUsers(null, pageable);

            assertThat(response.content()).hasSize(1);
            assertThat(response.content().get(0).username()).isEqualTo("alice");
        }

        @Test
        @DisplayName("should filter by keyword when keyword is provided")
        void withKeyword() {
            PageRequest pageable = PageRequest.of(0, 10);
            Users user = Users.builder().id(2L).username("bob").build();
            when(userRepository.findByUsernameContainingIgnoreCaseOrNameContainingIgnoreCase("bob", "bob", pageable))
                    .thenReturn(new PageImpl<>(List.of(user)));

            AccessPageResponse<AccessUserSummaryResponse> response = service.searchUsers("bob", pageable);

            assertThat(response.content()).hasSize(1);
            assertThat(response.content().get(0).username()).isEqualTo("bob");
        }
    }

    @Nested
    @DisplayName("getUserDetail")
    class GetUserDetail {
        @Test
        @DisplayName("should throw exception when user is not found")
        void notFound() {
            when(userRepository.findByIdWithGroupsRolesAndPermissions(999L)).thenReturn(Optional.empty());

            assertThrows(IllegalArgumentException.class, () -> service.getUserDetail(999L));
        }

        @Test
        @DisplayName("should map user group, roles, and permissions correctly")
        void success() {
            Permission p1 = Permission.builder().name("READ").friendlyName("Read Access").build();
            Permission p2 = Permission.builder().name("WRITE").friendlyName("Write Access").build();

            Role r1 = Role.builder().id(10L).roleName("ROLE_USER").roleDesc("Desc1").build();
            r1.setRolePermissions(Set.of(RolePermission.builder().role(r1).permission(p1).build()));

            Role r2 = Role.builder().id(11L).roleName("ROLE_GROUP").roleDesc("Desc2").build();
            r2.setRolePermissions(Set.of(RolePermission.builder().role(r2).permission(p2).build()));

            Group g1 = Group.builder().id(20L).name("GroupA").build();
            g1.setGroupRoles(Set.of(GroupRole.builder().group(g1).role(r2).build()));

            Users user = Users.builder()
                    .id(1L)
                    .username("alice")
                    .name("Alice")
                    .email("alice@test.com")
                    .enabled(true)
                    .build();

            Set<UserGroup> userGroups = new HashSet<>(List.of(UserGroup.builder().user(user).group(g1).build()));
            Set<UserRole> userRoles = new HashSet<>(List.of(UserRole.builder().user(user).role(r1).build()));
            user.setUserGroups(userGroups);
            user.setUserRoles(userRoles);

            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));

            AccessUserDetailResponse result = service.getUserDetail(1L);

            assertThat(result.id()).isEqualTo(1L);
            assertThat(result.groups()).hasSize(1);
            assertThat(result.groups().get(0).name()).isEqualTo("GroupA");
            assertThat(result.directRoles()).hasSize(1);
            assertThat(result.directRoles().get(0).name()).isEqualTo("ROLE_USER");
            assertThat(result.groupRoles()).hasSize(1);
            assertThat(result.groupRoles().get(0).name()).isEqualTo("ROLE_GROUP");
            assertThat(result.permissions()).hasSize(2);
        }
    }

    @Nested
    @DisplayName("updateUserGroups")
    class UpdateUserGroups {
        @Test
        @DisplayName("should update user groups successfully")
        void success() {
            Users user = Users.builder().id(1L).build();
            user.setUserGroups(new HashSet<>());
            Group group = Group.builder().id(10L).build();

            when(userRepository.findById(1L)).thenReturn(Optional.of(user));
            when(groupRepository.findById(10L)).thenReturn(Optional.of(group));

            UpdateUserGroupsRequest req = new UpdateUserGroupsRequest();
            req.setGroupIds(List.of(10L));

            AccessActionResponse res = service.updateUserGroups(1L, req);

            assertThat(res.success()).isTrue();
            verify(userRepository).save(user);
            assertThat(user.getUserGroups()).hasSize(1);
        }
    }

    @Nested
    @DisplayName("updateUserDirectRoles")
    class UpdateUserDirectRoles {
        @Test
        @DisplayName("should assign explicit role and crud assignments")
        void explicitAssignments() {
            Users user = Users.builder().id(1L).build();
            user.setUserRoles(new HashSet<>());
            Role role = Role.builder().id(10L).build();
            Permission readPerm = Permission.builder().id(50L).name("READ").build();

            when(userRepository.findById(1L)).thenReturn(Optional.of(user));
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));
            when(permissionRepository.findByName("READ")).thenReturn(Optional.of(readPerm));

            AccessRoleAssignmentRequest assignment = new AccessRoleAssignmentRequest();
            assignment.setRoleId(10L);
            assignment.setCrudPermissions(List.of("READ"));
            assignment.setExtraPermissionIds(List.of());

            AccessRoleAssignmentsRequest request = new AccessRoleAssignmentsRequest();
            request.setRoleAssignments(List.of(assignment));

            AccessActionResponse res = service.updateUserDirectRoles(1L, request);

            assertThat(res.success()).isTrue();
            verify(userRolePermissionRepository).save(any(UserRolePermission.class));
            verify(userRepository).save(user);
        }

        @Test
        @DisplayName("should assign roles and copy its crud permissions when assignments are null")
        void nullAssignments() {
            Users user = Users.builder().id(1L).build();
            user.setUserRoles(new HashSet<>());
            Permission readPerm = Permission.builder().id(50L).name("READ").build();
            Role role = Role.builder().id(10L).build();
            role.setRolePermissions(Set.of(RolePermission.builder().role(role).permission(readPerm).build()));

            when(userRepository.findById(1L)).thenReturn(Optional.of(user));
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));

            AccessRoleAssignmentsRequest request = new AccessRoleAssignmentsRequest();
            request.setRoleIds(List.of(10L));

            AccessActionResponse res = service.updateUserDirectRoles(1L, request);

            assertThat(res.success()).isTrue();
            verify(userRolePermissionRepository).save(any(UserRolePermission.class));
            verify(userRepository).save(user);
        }
    }

    @Nested
    @DisplayName("groups and roles endpoints")
    class GroupsAndRoles {
        @Test
        @DisplayName("should return group detail and members")
        void groupDetail() {
            Group group = Group.builder().id(10L).name("GroupA").build();
            group.setGroupRoles(Set.of());
            when(groupRepository.findById(10L)).thenReturn(Optional.of(group));

            Users member = Users.builder().id(1L).username("alice").build();
            member.setUserGroups(new HashSet<>(List.of(UserGroup.builder().user(member).group(group).build())));
            when(userRepository.findAll()).thenReturn(List.of(member));

            AccessGroupDetailResponse res = service.getGroupDetail(10L);

            assertThat(res.id()).isEqualTo(10L);
            assertThat(res.members()).hasSize(1);
            assertThat(res.members().get(0).username()).isEqualTo("alice");
        }

        @Test
        @DisplayName("should return role detail and direct users")
        void roleDetail() {
            Role role = Role.builder().id(5L).roleName("ROLE_USER").build();
            role.setRolePermissions(Set.of());
            when(roleService.getRole(5L)).thenReturn(role);

            Users user = Users.builder().id(1L).username("alice").build();
            UserRole ur = UserRole.builder().user(user).role(role).build();
            when(userRoleRepository.findByRoleIdWithUser(5L)).thenReturn(List.of(ur));

            AccessRoleDetailResponse res = service.getRoleDetail(5L);

            assertThat(res.id()).isEqualTo(5L);
            assertThat(res.directUsers()).hasSize(1);
            assertThat(res.directUsers().get(0).username()).isEqualTo("alice");
        }
    }

    @Nested
    @DisplayName("getAllRolesSimple")
    class GetAllRolesSimple {
        @Test
        @DisplayName("should separate CRUD permissions from extra permissions")
        void separation() {
            Permission read = Permission.builder().id(1L).name("READ").build();
            Permission custom = Permission.builder().id(2L).name("CUSTOM").friendlyName("F").build();

            Role role = Role.builder().id(10L).roleName("ROLE_USER").build();
            role.setRolePermissions(Set.of(
                    RolePermission.builder().role(role).permission(read).build(),
                    RolePermission.builder().role(role).permission(custom).build()
            ));

            when(roleRepository.findAllWithPermissions()).thenReturn(List.of(role));

            List<AccessRoleOptionResponse> res = service.getAllRolesSimple();

            assertThat(res).hasSize(1);
            assertThat(res.get(0).crudPermissions()).containsExactly("READ");
            assertThat(res.get(0).extraPermissions()).hasSize(1);
            assertThat(res.get(0).extraPermissions().get(0).name()).isEqualTo("CUSTOM");
        }
    }

    @Nested
    @DisplayName("cruds and helper query tests")
    class HelperQuery {
        @Test
        @DisplayName("should fetch user role cruds")
        void userRoleCruds() {
            Permission read = Permission.builder().name("READ").build();
            UserRolePermission urp = new UserRolePermission();
            urp.setPermission(read);

            when(userRolePermissionRepository.findByUserIdAndRoleId(1L, 10L)).thenReturn(List.of(urp));

            List<String> res = service.getUserRoleCruds(1L, 10L);

            assertThat(res).containsExactly("READ");
        }

        @Test
        @DisplayName("should fetch group role cruds")
        void groupRoleCruds() {
            Permission write = Permission.builder().name("WRITE").build();
            GroupRolePermission grp = new GroupRolePermission();
            grp.setPermission(write);

            when(groupRolePermissionRepository.findByGroupIdAndRoleId(2L, 20L)).thenReturn(List.of(grp));

            List<String> res = service.getGroupRoleCruds(2L, 20L);

            assertThat(res).containsExactly("WRITE");
        }
    }
}
