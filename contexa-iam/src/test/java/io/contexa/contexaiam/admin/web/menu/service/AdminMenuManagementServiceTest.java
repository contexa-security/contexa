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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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

        when(adminMenuService.getMenuById(1L)).thenReturn(Optional.of(AdminMenu.builder().id(1L).name("Top").build()));
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

    private AdminMenuSaveRequest request(String name, String dataPage, String menuType, String parentId) {
        AdminMenuSaveRequest req = new AdminMenuSaveRequest();
        req.setName(name);
        req.setDataPage(dataPage);
        req.setMenuType(menuType);
        req.setParentId(parentId);
        return req;
    }

    @Test
    @DisplayName("a menu without a name, with a name of the built-in menus or longer than its column is not created")
    void aMenuWithoutAUsableNameIsNotCreated() {
        for (String name : new String[]{null, "", "   ", "menu.custom", "M".repeat(101)}) {
            AdminMenuSaveRequest req = request(name, null, "CORE", null);
            assertThatThrownBy(() -> service.createMenu(req))
                    .isInstanceOf(IllegalArgumentException.class);
        }
        verify(adminMenuService, never()).saveMenu(any());
    }

    @Test
    @DisplayName("a menu of a kind the console does not know, under a parent that is not a top menu, or with a data page "
            + "taken is not created")
    void aMenuWithAWrongPlaceIsNotCreated() {
        AdminMenu child = AdminMenu.builder().id(2L).name("Child").parentId(1L).build();
        lenient().when(adminMenuService.getMenuById(999999L)).thenReturn(Optional.empty());
        lenient().when(adminMenuService.getMenuById(2L)).thenReturn(Optional.of(child));
        lenient().when(adminMenuService.getMenusByDataPage("users"))
                .thenReturn(List.of(AdminMenu.builder().id(13L).name("menu.iam.users").dataPage("users").build()));

        for (AdminMenuSaveRequest req : List.of(request("Odd", null, "ODD", null), request("Orphan", null, "CORE", "999999"),
                request("Deep", null, "CORE", "2"), request("Twin", "users", "CORE", null),
                request("Long", "d".repeat(51), "CORE", null))) {
            assertThatThrownBy(() -> service.createMenu(req))
                    .isInstanceOf(IllegalArgumentException.class);
        }
        verify(adminMenuService, never()).saveMenu(any());
    }

    @Test
    @DisplayName("the name and data page of a built-in menu stay; its other fields can change")
    void aBuiltInMenuKeepsItsNameAndDataPage() {
        AdminMenu settings = AdminMenu.builder().id(17L).name("menu.iam.system.settings").dataPage("system-settings")
                .url("/contexa/admin/system-settings").parentId(4L).menuType("CORE").menuOrder(7).build();
        when(adminMenuService.getMenuById(17L)).thenReturn(Optional.of(settings));

        assertThatThrownBy(() -> service.updateMenu(17L, request("Settings", "system-settings", "CORE", "4")))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("msg.menu.system.locked");
        assertThatThrownBy(() -> service.updateMenu(17L, request("menu.iam.system.settings", "other", "CORE", "4")))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("msg.menu.system.locked");
        verify(adminMenuService, never()).saveMenu(any());

        AdminMenuSaveRequest reorder = request("menu.iam.system.settings", "system-settings", "CORE", "4");
        reorder.setMenuOrder("9");
        assertThat(service.updateMenu(17L, reorder).success()).isTrue();
        assertThat(settings.getMenuOrder()).isEqualTo(9);
    }

    @Test
    @DisplayName("a menu that holds a built-in menu is not deleted; one that holds its own submenus is, with them")
    void deletingAMenuWithSubmenus() {
        AdminMenu custom = AdminMenu.builder().id(30L).name("Custom group").build();
        when(adminMenuService.getMenuById(30L)).thenReturn(Optional.of(custom));
        when(adminMenuService.getDescendants(30L)).thenReturn(List.of(
                AdminMenu.builder().id(31L).name("menu.iam.users").parentId(30L).build()));

        assertThat(service.deleteMenu(30L)).get().extracting(AdminMenuActionResponse::success).isEqualTo(false);
        verify(adminMenuService, never()).deleteMenu(anyLong());

        when(adminMenuService.getDescendants(30L)).thenReturn(List.of(
                AdminMenu.builder().id(32L).name("Own child").parentId(30L).build()));
        assertThat(service.deleteMenu(30L)).get().extracting(AdminMenuActionResponse::success).isEqualTo(true);
        verify(adminMenuService).deleteMenu(30L);
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
    @DisplayName("a stored icon of no known form stays off the list and the edit form")
    void aStoredIconOfNoKnownFormIsNotHandedOut() {
        AdminMenu menu = AdminMenu.builder().id(3L).name("Custom").icon("<b>Sales & Ops</b>").build();
        when(adminMenuService.getAllMenus()).thenReturn(List.of(menu));
        when(adminMenuService.getMenuById(3L)).thenReturn(Optional.of(menu));

        assertThat(service.getPageModel().menus()).extracting(AdminMenuView::icon).containsExactly("");
        assertThat(service.getMenu(3L)).map(AdminMenuResponse::icon).contains("");
    }

    @Test
    @DisplayName("a stored address outside the application stays on the list and the edit form as text, to be fixed there")
    void aStoredAddressOutsideTheApplicationStaysVisibleForFixing() {
        AdminMenu menu = AdminMenu.builder().id(5L).name("Custom").url("javascript:alert(1)").build();
        when(adminMenuService.getAllMenus()).thenReturn(List.of(menu));
        when(adminMenuService.getMenuById(5L)).thenReturn(Optional.of(menu));

        assertThat(service.getPageModel().menus()).extracting(AdminMenuView::url).containsExactly("javascript:alert(1)");
        assertThat(service.getMenu(5L)).map(AdminMenuResponse::url).contains("javascript:alert(1)");
    }

    @Test
    @DisplayName("a seeded drawing goes on reaching the list and the edit form")
    void aSeededDrawingIsHandedOut() {
        String drawing = "<svg fill=\"none\" stroke=\"currentColor\" viewBox=\"0 0 24 24\" width=\"24\" height=\"24\">"
                + "<path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"1.5\" d=\"M3.75 21h16.5\"/></svg>";
        AdminMenu menu = AdminMenu.builder().id(4L).name("menu.dashboard").icon(drawing).build();
        when(adminMenuService.getAllMenus()).thenReturn(List.of(menu));
        when(adminMenuService.getMenuById(4L)).thenReturn(Optional.of(menu));

        assertThat(service.getPageModel().menus()).extracting(AdminMenuView::icon).containsExactly(drawing);
        assertThat(service.getMenu(4L)).map(AdminMenuResponse::icon).contains(drawing);
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
