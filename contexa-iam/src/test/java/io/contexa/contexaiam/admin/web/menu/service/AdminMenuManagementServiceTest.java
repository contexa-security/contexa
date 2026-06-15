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
package io.contexa.contexaiam.admin.web.menu.service;

import io.contexa.contexacommon.entity.AdminMenu;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexaiam.admin.web.menu.dto.AdminMenuDtos.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.MessageSource;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AdminMenuManagementService")
class AdminMenuManagementServiceTest {

    @Mock private AdminMenuService adminMenuService;
    @Mock private RoleRepository roleRepository;
    @Mock private MessageSource messageSource;

    @InjectMocks
    private AdminMenuManagementService service;

    @BeforeEach
    void setUp() {
        lenient().when(messageSource.getMessage(anyString(), any(), any(Locale.class)))
                .thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    @DisplayName("getPageModel should sort parent-child menus and fetch roles")
    void getPageModel() {
        AdminMenu m1 = AdminMenu.builder().id(1L).name("P1").menuOrder(2).build();
        AdminMenu m2 = AdminMenu.builder().id(2L).name("C1").parentId(1L).menuOrder(1).build();

        when(adminMenuService.getAllMenus()).thenReturn(List.of(m1, m2));
        when(roleRepository.findAll()).thenReturn(List.of(Role.builder().roleName("ROLE_ADMIN").build()));

        AdminMenuPageModel model = service.getPageModel();

        assertThat(model.menus()).hasSize(2);
        assertThat(model.menus().get(0).id()).isEqualTo(1L); // Parent first
        assertThat(model.menus().get(1).id()).isEqualTo(2L); // Child next
        assertThat(model.parentIds()).containsExactly(1L);
        assertThat(model.allRoles()).extracting(AdminRoleOptionView::roleName).containsExactly("ROLE_ADMIN");
    }

    @Test
    @DisplayName("toggleMenu should call adminMenuService.toggleEnabled")
    void toggleMenu() {
        AdminMenuActionResponse res = service.toggleMenu(1L);
        assertThat(res.success()).isTrue();
        verify(adminMenuService).toggleEnabled(1L);
    }

    @Test
    @DisplayName("updateRoles should call adminMenuService.updateMenuRoles")
    void updateRoles() {
        AdminMenuRolesRequest req = new AdminMenuRolesRequest(List.of("ADMIN"));

        AdminMenuActionResponse res = service.updateRoles(1L, req);
        assertThat(res.success()).isTrue();
        verify(adminMenuService).updateMenuRoles(eq(1L), anySet());
    }

    @Test
    @DisplayName("updateOrder should call adminMenuService.updateMenuOrder for each item")
    void updateOrder() {
        AdminMenuOrderRequest r1 = new AdminMenuOrderRequest("10", "5");
        AdminMenuOrderRequest r2 = new AdminMenuOrderRequest("11", "6");

        AdminMenuActionResponse res = service.updateOrder(List.of(r1, r2));
        assertThat(res.success()).isTrue();
        verify(adminMenuService).updateMenuOrder(10L, 5);
        verify(adminMenuService).updateMenuOrder(11L, 6);
    }

    @Test
    @DisplayName("createMenu should create AdminMenu entity and save")
    void createMenu() {
        AdminMenuSaveRequest req = new AdminMenuSaveRequest();
        req.setName("Custom");
        req.setUrl("/url");
        req.setMenuType("CORE");
        req.setParentId("1");
        req.setMenuOrder("5");
        req.setEnabled("true");

        when(adminMenuService.saveMenu(any())).thenAnswer(inv -> {
            AdminMenu menu = inv.getArgument(0);
            menu.setId(99L);
            return menu;
        });

        AdminMenuActionResponse res = service.createMenu(req);
        assertThat(res.success()).isTrue();
        assertThat(res.id()).isEqualTo(99L);
        verify(adminMenuService).saveMenu(any(AdminMenu.class));
    }

    @Test
    @DisplayName("updateMenu should return error when menu not found")
    void updateMenuNotFound() {
        when(adminMenuService.getMenuById(404L)).thenReturn(Optional.empty());

        AdminMenuActionResponse res = service.updateMenu(404L, new AdminMenuSaveRequest());
        assertThat(res.success()).isFalse();
        assertThat(res.error()).isEqualTo("msg.menu.not.found");
    }

    @Test
    @DisplayName("updateMenu should modify properties and save when found")
    void updateMenuSuccess() {
        AdminMenu menu = AdminMenu.builder().id(10L).name("Old").enabled(true).build();
        when(adminMenuService.getMenuById(10L)).thenReturn(Optional.of(menu));

        AdminMenuSaveRequest req = new AdminMenuSaveRequest();
        req.setName("New");
        req.setEnabled("false");

        AdminMenuActionResponse res = service.updateMenu(10L, req);
        assertThat(res.success()).isTrue();
        assertThat(menu.getName()).isEqualTo("New");
        assertThat(menu.isEnabled()).isFalse();
        verify(adminMenuService).saveMenu(menu);
    }

    @Test
    @DisplayName("deleteMenu should block system menu delete")
    void deleteMenuSystem() {
        AdminMenu menu = AdminMenu.builder().id(1L).name("menu.dashboard").build();
        when(adminMenuService.getMenuById(1L)).thenReturn(Optional.of(menu));

        Optional<AdminMenuActionResponse> res = service.deleteMenu(1L);
        assertThat(res).isPresent();
        assertThat(res.get().success()).isFalse();
        assertThat(res.get().error()).isEqualTo("msg.menu.system.cannot.delete");
        verify(adminMenuService, never()).deleteMenu(anyLong());
    }

    @Test
    @DisplayName("deleteMenu should allow custom menu delete")
    void deleteMenuCustom() {
        AdminMenu menu = AdminMenu.builder().id(2L).name("Custom").build();
        when(adminMenuService.getMenuById(2L)).thenReturn(Optional.of(menu));

        Optional<AdminMenuActionResponse> res = service.deleteMenu(2L);
        assertThat(res).isPresent();
        assertThat(res.get().success()).isTrue();
        verify(adminMenuService).deleteMenu(2L);
    }
}
