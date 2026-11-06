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
package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.LastAdministratorException;
import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.impl.RoleHierarchyService;
import io.contexa.contexaiam.admin.web.center.AccessCenterController;
import io.contexa.contexaiam.admin.web.center.service.AccessCenterService;
import io.contexa.contexaiam.testsupport.I18nTestSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.modelmapper.ModelMapper;
import org.springframework.context.MessageSource;
import org.springframework.data.domain.PageImpl;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/**
 * An edit of a role, a group or the role hierarchy that would take the console's last administrator is answered with a
 * 409 and the reason on the page the person came from, as a change of a user is: the controllers that catch the
 * exceptions of a form let this one through.
 */
@ExtendWith(I18nTestSupport.EnglishLocale.class)
class LastAdministratorScreensTest {

    private static final LastAdministratorException REFUSAL = new LastAdministratorException("no administrator left");

    private final MessageSource messages = I18nTestSupport.englishMessageSource();
    private final RoleService roleService = mock(RoleService.class);
    private final GroupService groupService = mock(GroupService.class);
    private final RoleHierarchyService hierarchyService = mock(RoleHierarchyService.class);
    private final AccessCenterService accessCenter = mock(AccessCenterService.class);
    private final ModelMapper mapper = mock(ModelMapper.class);

    private MockMvc roles;
    private MockMvc groups;
    private MockMvc hierarchies;
    private MockMvc center;

    @BeforeEach
    void screens() {
        when(roleService.searchRoles(any(), any())).thenReturn(new PageImpl<>(List.of()));
        when(groupService.searchGroups(any(), any())).thenReturn(new PageImpl<>(List.of()));
        when(hierarchyService.searchRoleHierarchies(any(), any())).thenReturn(new PageImpl<>(List.of()));
        roles = MockMvcBuilders.standaloneSetup(
                new RoleController(roleService, mock(PermissionService.class), mapper, messages)).build();
        groups = MockMvcBuilders.standaloneSetup(new GroupController(groupService, roleService, mapper, messages)).build();
        hierarchies = MockMvcBuilders.standaloneSetup(
                new RoleHierarchyController(hierarchyService, mapper, roleService, groupService, messages)).build();
        center = MockMvcBuilders.standaloneSetup(new AccessCenterController(accessCenter)).build();
    }

    @Test
    @DisplayName("deleting the role of the last administrator answers 409 with the reason on the list of roles")
    void deletingARole() throws Exception {
        doThrow(REFUSAL).when(roleService).deleteRole(5L);

        roles.perform(post("/contexa/admin/roles/delete/5"))
                .andExpect(status().isConflict())
                .andExpect(view().name("contexa/admin/roles"))
                .andExpect(model().attribute("errorMessage", "no administrator left"));
    }

    @Test
    @DisplayName("renaming the role of the last administrator answers 409 with the reason on the list of roles")
    void renamingARole() throws Exception {
        doThrow(REFUSAL).when(roleService).updateRole(any(), any());

        roles.perform(post("/contexa/admin/roles/5/edit").param("roleName", "ROLE_ROOT"))
                .andExpect(status().isConflict())
                .andExpect(model().attribute("errorMessage", "no administrator left"));
    }

    @Test
    @DisplayName("taking the role from the group of the last administrator answers 409 with the reason on the list of groups")
    void changingAGroup() throws Exception {
        doThrow(REFUSAL).when(groupService).updateGroup(any(), any());

        groups.perform(post("/contexa/admin/groups/3/edit").param("name", "ops"))
                .andExpect(status().isConflict())
                .andExpect(view().name("contexa/admin/groups"))
                .andExpect(model().attribute("errorMessage", "no administrator left"));
    }

    @Test
    @DisplayName("deleting the group of the last administrator answers 409 with the reason on the list of groups")
    void deletingAGroup() throws Exception {
        doThrow(REFUSAL).when(groupService).deleteGroup(3L);

        groups.perform(post("/contexa/admin/groups/delete/3"))
                .andExpect(status().isConflict())
                .andExpect(model().attribute("errorMessage", "no administrator left"));
    }

    @Test
    @DisplayName("rewriting, deleting or switching off the hierarchy of the last administrator answers 409 with the reason")
    void changingTheHierarchy() throws Exception {
        doThrow(REFUSAL).when(hierarchyService).updateRoleHierarchy(any());
        doThrow(REFUSAL).when(hierarchyService).deleteRoleHierarchy(2L);
        doThrow(REFUSAL).when(hierarchyService).activateRoleHierarchy(2L);

        for (String path : List.of("/contexa/admin/role-hierarchies/2/edit", "/contexa/admin/role-hierarchies/delete/2",
                "/contexa/admin/role-hierarchies/2/activate")) {
            hierarchies.perform(post(path))
                    .andExpect(status().isConflict())
                    .andExpect(view().name("contexa/admin/role-hierarchies"))
                    .andExpect(model().attribute("error", "no administrator left"));
        }
    }

    @Test
    @DisplayName("taking the role from the group in the access center answers 409 with the reason")
    void changingAGroupInTheAccessCenter() throws Exception {
        when(accessCenter.updateGroupRoles(eq(3L), any())).thenThrow(REFUSAL);

        center.perform(post("/contexa/admin/access-center/api/groups/3/roles")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"roleIds\": []}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("no administrator left"));
    }
}
