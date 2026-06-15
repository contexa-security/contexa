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
package io.contexa.contexaiam.admin.web.center;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.GroupRole;
import io.contexa.contexacommon.entity.GroupRolePermission;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.RolePermission;
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
import io.contexa.contexaiam.admin.web.center.service.AccessCenterService;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.quality.Strictness;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.web.PageableHandlerMethodArgumentResolver;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;


@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("AccessCenterController contract")
class AccessCenterControllerTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private UserRoleRepository userRoleRepository;

    @Mock
    private GroupRepository groupRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PermissionRepository permissionRepository;

    @Mock
    private RoleService roleService;

    @Mock
    private UserRolePermissionRepository userRolePermissionRepository;

    @Mock
    private GroupRolePermissionRepository groupRolePermissionRepository;

    private AccessCenterController controller;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        AccessCenterService accessCenterService = new AccessCenterService(
                userRepository,
                userRoleRepository,
                groupRepository,
                roleRepository,
                permissionRepository,
                roleService,
                userRolePermissionRepository,
                groupRolePermissionRepository
        );
        controller = new AccessCenterController(accessCenterService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setCustomArgumentResolvers(new PageableHandlerMethodArgumentResolver())
                .build();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Nested
    @DisplayName("page")
    class Page {

        @Test
        @DisplayName("keeps existing view and model contract")
        void accessCenterPage() throws Exception {
            when(userRepository.count()).thenReturn(10L);
            when(groupRepository.count()).thenReturn(2L);
            when(roleRepository.count()).thenReturn(3L);
            when(permissionRepository.count()).thenReturn(4L);

            mockMvc.perform(get("/contexa/admin/access-center").param("tab", "roles"))
                    .andExpect(status().isOk())
                    .andExpect(view().name("contexa/admin/access-center"))
                    .andExpect(model().attribute("activePage", "access-center"))
                    .andExpect(model().attribute("activeTab", "roles"))
                    .andExpect(model().attribute("userCount", 10L))
                    .andExpect(model().attribute("groupCount", 2L))
                    .andExpect(model().attribute("roleCount", 3L))
                    .andExpect(model().attribute("permissionCount", 4L));
        }

        @Test
        @DisplayName("direct method keeps existing model contract")
        void accessCenterPageDirect() {
            Model model = new ConcurrentModel();
            when(userRepository.count()).thenReturn(10L);
            when(groupRepository.count()).thenReturn(2L);
            when(roleRepository.count()).thenReturn(3L);
            when(permissionRepository.count()).thenReturn(4L);

            String viewName = controller.accessCenter("users", model);

            assertThat(viewName).isEqualTo("contexa/admin/access-center");
            assertThat(model.getAttribute("activePage")).isEqualTo("access-center");
            assertThat(model.getAttribute("activeTab")).isEqualTo("users");
            assertThat(model.getAttribute("userCount")).isEqualTo(10L);
            assertThat(model.getAttribute("groupCount")).isEqualTo(2L);
            assertThat(model.getAttribute("roleCount")).isEqualTo(3L);
            assertThat(model.getAttribute("permissionCount")).isEqualTo(4L);
        }
    }

    @Nested
    @DisplayName("users")
    class UsersApi {

        @Test
        @DisplayName("search keeps existing page JSON fields")
        void searchUsers() throws Exception {
            Users user = Users.builder()
                    .id(1L)
                    .username("alice")
                    .name("Alice")
                    .email("alice@example.com")
                    .department("Engineering")
                    .enabled(true)
                    .build();
            when(userRepository.findByUsernameContainingIgnoreCaseOrNameContainingIgnoreCase(
                    any(), any(), any()))
                    .thenReturn(new PageImpl<>(List.of(user), PageRequest.of(0, 20), 1));

            mockMvc.perform(get("/contexa/admin/access-center/api/users")
                            .param("keyword", "ali")
                            .param("page", "0")
                            .param("size", "20"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.content[0].id").value(1))
                    .andExpect(jsonPath("$.content[0].username").value("alice"))
                    .andExpect(jsonPath("$.content[0].name").value("Alice"))
                    .andExpect(jsonPath("$.content[0].email").value("alice@example.com"))
                    .andExpect(jsonPath("$.content[0].enabled").value(true))
                    .andExpect(jsonPath("$.content[0].department").value("Engineering"))
                    .andExpect(jsonPath("$.totalElements").value(1))
                    .andExpect(jsonPath("$.totalPages").value(1));
        }

        @Test
        @DisplayName("detail keeps existing nested JSON fields")
        void getUserDetail() throws Exception {
            Users user = userWithRelations();
            when(userRepository.findByIdWithGroupsRolesAndPermissions(1L)).thenReturn(Optional.of(user));

            mockMvc.perform(get("/contexa/admin/access-center/api/users/1/detail"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(1))
                    .andExpect(jsonPath("$.username").value("alice"))
                    .andExpect(jsonPath("$.groups[0].id").value(20))
                    .andExpect(jsonPath("$.groups[0].name").value("Operators"))
                    .andExpect(jsonPath("$.directRoles[0].source").value("direct"))
                    .andExpect(jsonPath("$.groupRoles[0].source").value("group"))
                    .andExpect(jsonPath("$.groupRoles[0].groupName").value("Operators"))
                    .andExpect(jsonPath("$.permissions[*].name", containsInAnyOrder("READ", "WRITE")))
                    .andExpect(jsonPath("$.permissions[*].source", containsInAnyOrder("direct", "group")));
        }

        @Test
        @DisplayName("detail returns not found instead of server error for missing user")
        void getUserDetailNotFound() throws Exception {
            when(userRepository.findByIdWithGroupsRolesAndPermissions(404L)).thenReturn(Optional.empty());

            mockMvc.perform(get("/contexa/admin/access-center/api/users/404/detail"))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("group update keeps existing success JSON")
        void updateUserGroups() throws Exception {
            Users user = Users.builder().id(1L).username("alice").name("Alice").build();
            Group group = Group.builder().id(20L).name("Operators").build();
            when(userRepository.findById(1L)).thenReturn(Optional.of(user));
            when(groupRepository.findById(20L)).thenReturn(Optional.of(group));

            mockMvc.perform(post("/contexa/admin/access-center/api/users/1/groups")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"groupIds\":[20]}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true))
                    .andExpect(jsonPath("$.message").value("Groups updated successfully."));

            verify(userRepository).save(user);
            assertThat(user.getUserGroups()).hasSize(1);
        }

        @Test
        @DisplayName("group update rejects explicit null groupIds instead of treating it as empty")
        void updateUserGroupsRejectsExplicitNullGroupIds() throws Exception {
            Users user = Users.builder().id(1L).username("alice").name("Alice").build();
            when(userRepository.findById(1L)).thenReturn(Optional.of(user));

            mockMvc.perform(post("/contexa/admin/access-center/api/users/1/groups")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"groupIds\":null}"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success").value(false));
        }

        @Test
        @DisplayName("group update keeps missing groupIds compatible as empty")
        void updateUserGroupsTreatsMissingGroupIdsAsEmpty() throws Exception {
            Users user = Users.builder().id(1L).username("alice").name("Alice").build();
            when(userRepository.findById(1L)).thenReturn(Optional.of(user));

            mockMvc.perform(post("/contexa/admin/access-center/api/users/1/groups")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true));

            verify(userRepository).save(user);
            assertThat(user.getUserGroups()).isEmpty();
        }

        @Test
        @DisplayName("direct role assignment keeps roleAssignments request contract and READ auto-add")
        void updateUserDirectRolesWithAssignments() throws Exception {
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken("auditor", "n/a"));
            Users user = Users.builder().id(1L).username("alice").name("Alice").build();
            Role role = Role.builder().id(10L).roleName("ADMIN").build();
            Permission read = Permission.builder().id(100L).name("READ").build();
            Permission delete = Permission.builder().id(101L).name("DELETE").build();
            when(userRepository.findById(1L)).thenReturn(Optional.of(user));
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));
            when(permissionRepository.findByName("READ")).thenReturn(Optional.of(read));
            when(permissionRepository.findByName("DELETE")).thenReturn(Optional.of(delete));

            mockMvc.perform(post("/contexa/admin/access-center/api/users/1/roles")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"roleAssignments":[{"roleId":10,"crudPermissions":["DELETE"]}]}
                                    """))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true))
                    .andExpect(jsonPath("$.message").value("Direct roles updated successfully."));

            verify(userRolePermissionRepository).deleteByUserId(1L);
            verify(userRolePermissionRepository).flush();
            verify(userRepository).save(user);
            assertThat(user.getUserRoles()).hasSize(1);

            ArgumentCaptor<UserRolePermission> captor = ArgumentCaptor.forClass(UserRolePermission.class);
            verify(userRolePermissionRepository, Mockito.times(2)).save(captor.capture());
            assertThat(captor.getAllValues())
                    .extracting(urp -> urp.getPermission().getName())
                    .containsExactlyInAnyOrder("READ", "DELETE");
            assertThat(captor.getAllValues())
                    .extracting(UserRolePermission::getAssignedBy)
                    .containsOnly("auditor");
        }

        @Test
        @DisplayName("direct role fallback rejects explicit null roleIds instead of treating it as empty")
        void updateUserDirectRolesRejectsExplicitNullRoleIds() throws Exception {
            Users user = Users.builder().id(1L).username("alice").name("Alice").build();
            when(userRepository.findById(1L)).thenReturn(Optional.of(user));

            mockMvc.perform(post("/contexa/admin/access-center/api/users/1/roles")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"roleIds\":null}"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success").value(false));
        }

        @Test
        @DisplayName("direct role assignment keeps missing CRUD permissions compatible with READ default")
        void updateUserDirectRolesTreatsMissingCrudPermissionsAsReadDefault() throws Exception {
            Users user = Users.builder().id(1L).username("alice").name("Alice").build();
            Role role = Role.builder().id(10L).roleName("ADMIN").build();
            Permission read = Permission.builder().id(100L).name("READ").build();
            when(userRepository.findById(1L)).thenReturn(Optional.of(user));
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));
            when(permissionRepository.findByName("READ")).thenReturn(Optional.of(read));

            mockMvc.perform(post("/contexa/admin/access-center/api/users/1/roles")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"roleAssignments":[{"roleId":10}]}
                                    """))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true));

            ArgumentCaptor<UserRolePermission> captor = ArgumentCaptor.forClass(UserRolePermission.class);
            verify(userRolePermissionRepository).save(captor.capture());
            assertThat(captor.getValue().getPermission().getName()).isEqualTo("READ");
        }

        @Test
        @DisplayName("direct role assignment rejects explicit null CRUD permissions instead of defaulting READ")
        void updateUserDirectRolesRejectsExplicitNullCrudPermissions() throws Exception {
            Users user = Users.builder().id(1L).username("alice").name("Alice").build();
            Role role = Role.builder().id(10L).roleName("ADMIN").build();
            Permission read = Permission.builder().id(100L).name("READ").build();
            when(userRepository.findById(1L)).thenReturn(Optional.of(user));
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));
            when(permissionRepository.findByName("READ")).thenReturn(Optional.of(read));

            mockMvc.perform(post("/contexa/admin/access-center/api/users/1/roles")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"roleAssignments":[{"roleId":10,"crudPermissions":null}]}
                                    """))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success").value(false));
        }
    }

    @Nested
    @DisplayName("groups")
    class GroupsApi {

        @Test
        @DisplayName("list keeps existing array JSON fields")
        void getAllGroups() throws Exception {
            when(groupRepository.findAll()).thenReturn(List.of(
                    Group.builder().id(20L).name("Operators").description("Ops group").build()));

            mockMvc.perform(get("/contexa/admin/access-center/api/groups"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].id").value(20))
                    .andExpect(jsonPath("$[0].name").value("Operators"))
                    .andExpect(jsonPath("$[0].description").value("Ops group"));
        }

        @Test
        @DisplayName("detail keeps existing roles and members fields")
        void getGroupDetail() throws Exception {
            Group group = groupWithRole();
            Users member = Users.builder().id(1L).username("alice").name("Alice").build();
            member.getUserGroups().add(UserGroup.builder().user(member).group(group).build());
            when(groupRepository.findById(20L)).thenReturn(Optional.of(group));
            when(userRepository.findAll()).thenReturn(List.of(member));

            mockMvc.perform(get("/contexa/admin/access-center/api/groups/20/detail"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(20))
                    .andExpect(jsonPath("$.name").value("Operators"))
                    .andExpect(jsonPath("$.roles[0].id").value(10))
                    .andExpect(jsonPath("$.roles[0].name").value("ADMIN"))
                    .andExpect(jsonPath("$.members[0].id").value(1))
                    .andExpect(jsonPath("$.members[0].username").value("alice"));
        }

        @Test
        @DisplayName("detail returns not found instead of server error for missing group")
        void getGroupDetailNotFound() throws Exception {
            when(groupRepository.findById(404L)).thenReturn(Optional.empty());

            mockMvc.perform(get("/contexa/admin/access-center/api/groups/404/detail"))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("role update keeps roleIds backward compatible request contract")
        void updateGroupRolesWithRoleIds() throws Exception {
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken("auditor", "n/a"));
            Group group = Group.builder().id(20L).name("Operators").build();
            Permission read = Permission.builder().id(100L).name("READ").targetType("CRUD").build();
            Permission data = Permission.builder().id(101L).name("DATA_VIEW").targetType("DATA").build();
            Role role = Role.builder().id(10L).roleName("ADMIN").build();
            role.getRolePermissions().add(RolePermission.builder().role(role).permission(read).build());
            role.getRolePermissions().add(RolePermission.builder().role(role).permission(data).build());
            when(groupRepository.findById(20L)).thenReturn(Optional.of(group));
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));

            mockMvc.perform(post("/contexa/admin/access-center/api/groups/20/roles")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"roleIds\":[10]}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true))
                    .andExpect(jsonPath("$.message").value("Group roles updated successfully."));

            verify(groupRolePermissionRepository).deleteByGroupId(20L);
            verify(groupRolePermissionRepository).flush();
            verify(groupRepository).save(group);
            assertThat(group.getGroupRoles()).hasSize(1);

            ArgumentCaptor<GroupRolePermission> captor = ArgumentCaptor.forClass(GroupRolePermission.class);
            verify(groupRolePermissionRepository).save(captor.capture());
            assertThat(captor.getValue().getPermission().getName()).isEqualTo("READ");
            assertThat(captor.getValue().getAssignedBy()).isEqualTo("auditor");
        }

        @Test
        @DisplayName("group role fallback rejects explicit null roleIds instead of treating it as empty")
        void updateGroupRolesRejectsExplicitNullRoleIds() throws Exception {
            Group group = Group.builder().id(20L).name("Operators").build();
            when(groupRepository.findById(20L)).thenReturn(Optional.of(group));

            mockMvc.perform(post("/contexa/admin/access-center/api/groups/20/roles")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"roleIds\":null}"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success").value(false));
        }
    }

    @Nested
    @DisplayName("roles and permissions")
    class RolesAndPermissionsApi {

        @Test
        @DisplayName("role list keeps existing fields")
        void getAllRoles() throws Exception {
            Role role = roleWithPermission();
            when(roleRepository.findAllWithPermissions()).thenReturn(List.of(role));

            mockMvc.perform(get("/contexa/admin/access-center/api/roles"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].id").value(10))
                    .andExpect(jsonPath("$[0].name").value("ADMIN"))
                    .andExpect(jsonPath("$[0].desc").value("Admin role"))
                    .andExpect(jsonPath("$[0].permCount").value(1));
        }

        @Test
        @DisplayName("role detail keeps existing permissions and directUsers fields")
        void getRoleDetail() throws Exception {
            Role role = roleWithPermission();
            Users user = Users.builder().id(1L).username("alice").name("Alice").build();
            when(roleService.getRole(10L)).thenReturn(role);
            when(userRoleRepository.findByRoleIdWithUser(10L))
                    .thenReturn(List.of(UserRole.builder().user(user).role(role).build()));

            mockMvc.perform(get("/contexa/admin/access-center/api/roles/10/detail"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(10))
                    .andExpect(jsonPath("$.name").value("ADMIN"))
                    .andExpect(jsonPath("$.permissions[0].id").value(100))
                    .andExpect(jsonPath("$.permissions[0].friendlyName").value("Read"))
                    .andExpect(jsonPath("$.directUsers[0].username").value("alice"));
        }

        @Test
        @DisplayName("detail returns not found instead of server error for missing role")
        void getRoleDetailNotFound() throws Exception {
            when(roleService.getRole(404L)).thenThrow(new IllegalArgumentException("Role not found"));

            mockMvc.perform(get("/contexa/admin/access-center/api/roles/404/detail"))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("role permission update keeps existing success JSON")
        void updateRolePermissions() throws Exception {
            Role role = Role.builder().id(10L).roleName("ADMIN").build();
            when(roleService.getRole(10L)).thenReturn(role);

            mockMvc.perform(post("/contexa/admin/access-center/api/roles/10/permissions")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"permissionIds\":[100,101]}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true))
                    .andExpect(jsonPath("$.message").value("Role permissions updated successfully."));

            verify(roleService).updateRole(role, List.of(100L, 101L));
        }

        @Test
        @DisplayName("role permission update rejects explicit null permissionIds instead of treating it as empty")
        void updateRolePermissionsRejectsExplicitNullPermissionIds() throws Exception {
            Role role = Role.builder().id(10L).roleName("ADMIN").build();
            when(roleService.getRole(10L)).thenReturn(role);

            mockMvc.perform(post("/contexa/admin/access-center/api/roles/10/permissions")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"permissionIds\":null}"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.success").value(false));
        }

        @Test
        @DisplayName("role permission update keeps missing permissionIds compatible as empty")
        void updateRolePermissionsTreatsMissingPermissionIdsAsEmpty() throws Exception {
            Role role = Role.builder().id(10L).roleName("ADMIN").build();
            when(roleService.getRole(10L)).thenReturn(role);

            mockMvc.perform(post("/contexa/admin/access-center/api/roles/10/permissions")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true));

            verify(roleService).updateRole(role, List.of());
        }

        @Test
        @DisplayName("all-roles returns role basics with no implicit CRUD fallback")
        void getAllRolesSimple() throws Exception {
            // Production now returns ONLY the CRUD permissions actually mapped to the
            // role. A role with no role-permission rows yields an empty crudPermissions
            // array (the JS layer renders all 4 chips with READ default-checked).
            Role role = Role.builder().id(10L).roleName("ADMIN").roleDesc("Admin role").build();
            when(roleRepository.findAllWithPermissions()).thenReturn(List.of(role));

            mockMvc.perform(get("/contexa/admin/access-center/api/all-roles"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].id").value(10))
                    .andExpect(jsonPath("$[0].name").value("ADMIN"))
                    .andExpect(jsonPath("$[0].crudPermissions").isArray())
                    .andExpect(jsonPath("$[0].crudPermissions").isEmpty());
        }

        @Test
        @DisplayName("all-permissions keeps existing fields")
        void getAllPermissions() throws Exception {
            Permission permission = Permission.builder()
                    .id(100L)
                    .name("READ")
                    .friendlyName("Read")
                    .description("Read access")
                    .build();
            when(permissionRepository.findAll()).thenReturn(List.of(permission));

            mockMvc.perform(get("/contexa/admin/access-center/api/all-permissions"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].id").value(100))
                    .andExpect(jsonPath("$[0].name").value("READ"))
                    .andExpect(jsonPath("$[0].friendlyName").value("Read"))
                    .andExpect(jsonPath("$[0].description").value("Read access"));
        }

        @Test
        @DisplayName("CRUD lookup endpoints keep existing string array contract")
        void getCruds() throws Exception {
            Permission read = Permission.builder().id(100L).name("READ").build();
            when(userRolePermissionRepository.findByUserIdAndRoleId(1L, 10L))
                    .thenReturn(List.of(new UserRolePermission(null, null, read, null, null)));
            when(groupRolePermissionRepository.findByGroupIdAndRoleId(20L, 10L))
                    .thenReturn(List.of(new GroupRolePermission(null, null, read, null, null)));

            mockMvc.perform(get("/contexa/admin/access-center/api/users/1/roles/10/cruds"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0]").value("READ"));

            mockMvc.perform(get("/contexa/admin/access-center/api/groups/20/roles/10/cruds"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0]").value("READ"));
        }
    }

    private Users userWithRelations() {
        Permission read = Permission.builder().id(100L).name("READ").friendlyName("Read").build();
        Permission write = Permission.builder().id(101L).name("WRITE").friendlyName("Write").build();

        Role directRole = Role.builder().id(10L).roleName("ADMIN").roleDesc("Admin role").build();
        directRole.getRolePermissions().add(RolePermission.builder().role(directRole).permission(read).build());

        Role groupRole = Role.builder().id(11L).roleName("OPERATOR").roleDesc("Operator role").build();
        groupRole.getRolePermissions().add(RolePermission.builder().role(groupRole).permission(write).build());

        Group group = Group.builder().id(20L).name("Operators").description("Ops group").build();
        group.getGroupRoles().add(GroupRole.builder().group(group).role(groupRole).build());

        Users user = Users.builder()
                .id(1L)
                .username("alice")
                .name("Alice")
                .email("alice@example.com")
                .department("Engineering")
                .enabled(true)
                .build();
        user.getUserGroups().add(UserGroup.builder().user(user).group(group).build());
        user.getUserRoles().add(UserRole.builder().user(user).role(directRole).build());
        return user;
    }

    private Group groupWithRole() {
        Role role = Role.builder().id(10L).roleName("ADMIN").roleDesc("Admin role").build();
        Group group = Group.builder().id(20L).name("Operators").description("Ops group").build();
        group.getGroupRoles().add(GroupRole.builder().group(group).role(role).build());
        return group;
    }

    private Role roleWithPermission() {
        Permission permission = Permission.builder()
                .id(100L)
                .name("READ")
                .friendlyName("Read")
                .description("Read access")
                .build();
        Role role = Role.builder().id(10L).roleName("ADMIN").roleDesc("Admin role").build();
        role.getRolePermissions().add(RolePermission.builder().role(role).permission(permission).build());
        return role;
    }
}
