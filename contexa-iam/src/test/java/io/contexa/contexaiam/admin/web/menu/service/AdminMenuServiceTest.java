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
import io.contexa.contexacommon.entity.AdminMenuRole;
import io.contexa.contexacommon.repository.AdminMenuRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AdminMenuService")
class AdminMenuServiceTest {

    @Mock
    private AdminMenuRepository menuRepository;

    @Mock
    private AdminMenuQueryCache menuQueryCache;

    @Test
    @DisplayName("initializeDefaultMenusIfEmpty should backfill missing menus when menus exist")
    void initializeDefaultMenusIfEmptyWhenNotEmpty() {
        AdminMenuService service = new AdminMenuService(menuRepository, menuQueryCache, false, false);
        when(menuRepository.count()).thenReturn(5L);
        when(menuRepository.findDuplicatedDataPages()).thenReturn(Collections.emptyList());
        when(menuRepository.findAllByDataPageOrderByIdAsc(anyString())).thenReturn(Collections.emptyList());
        when(menuRepository.save(any(AdminMenu.class))).thenAnswer(inv -> {
            AdminMenu menu = inv.getArgument(0);
            menu.setId(1L);
            return menu;
        });

        service.initializeDefaultMenusIfEmpty();

        verify(menuRepository, atLeastOnce()).save(any(AdminMenu.class));
        verify(menuRepository, atLeastOnce()).findDuplicatedDataPages();
    }

    @Test
    @DisplayName("initializeDefaultMenusIfEmpty should initialize default menus when empty")
    void initializeDefaultMenusIfEmptyWhenEmpty() {
        AdminMenuService service = new AdminMenuService(menuRepository, menuQueryCache, true, true);
        when(menuRepository.count()).thenReturn(0L);
        when(menuRepository.findDuplicatedDataPages()).thenReturn(Collections.emptyList());

        // We mock save to return mock AdminMenu with ID
        when(menuRepository.save(any(AdminMenu.class))).thenAnswer(inv -> {
            AdminMenu menu = inv.getArgument(0);
            menu.setId(1L);
            return menu;
        });

        service.initializeDefaultMenusIfEmpty();

        verify(menuRepository, atLeast(10)).save(any(AdminMenu.class));
        verify(menuQueryCache, atLeastOnce()).invalidate();
    }

    /** Console plan 5-1: a new installation gets the console's six screens and none of the AI monitor's pages. */
    @Test
    @DisplayName("a new installation seeds the Zero Trust console's six screens under the Zero Trust group")
    void aNewInstallationSeedsTheConsoleScreens() {
        AdminMenuService service = new AdminMenuService(menuRepository, menuQueryCache, false, false);
        List<AdminMenu> saved = new ArrayList<>();
        when(menuRepository.count()).thenReturn(0L);
        when(menuRepository.findDuplicatedDataPages()).thenReturn(Collections.emptyList());
        when(menuRepository.save(any(AdminMenu.class))).thenAnswer(inv -> {
            AdminMenu menu = inv.getArgument(0);
            if (menu.getId() == null) {
                menu.setId((long) saved.size() + 1);
            }
            saved.add(menu);
            return menu;
        });

        service.initializeDefaultMenusIfEmpty();

        Long group = saved.stream().filter(menu -> "ai-monitor".equals(menu.getDataPage())).findFirst()
                .orElseThrow().getId();
        List<String> screens = saved.stream().filter(menu -> group.equals(menu.getParentId()))
                .map(menu -> menu.getMenuOrder() + " " + menu.getName() + " " + menu.getUrl() + " " + menu.getDataPage())
                .distinct().toList();
        assertThat(screens).containsExactly(
                "1 menu.zerotrust.overview /contexa/admin/zero-trust zero-trust-overview",
                "2 menu.zerotrust.impact /contexa/admin/zero-trust/impact zero-trust-impact",
                "3 menu.zerotrust.trust /contexa/admin/zero-trust/trust zero-trust-trust",
                "4 menu.zerotrust.decisions /contexa/admin/zero-trust/decisions zero-trust-decisions",
                "5 menu.zerotrust.adoption /contexa/admin/zero-trust/adoption zero-trust-adoption",
                "6 menu.zerotrust.operations /contexa/admin/zero-trust/operations zero-trust-operations");
        assertThat(saved).noneMatch(menu -> menu.getDataPage() != null && menu.getDataPage().startsWith("ai-monitor-"));
        assertThat(saved).filteredOn(menu -> "security-monitor".equals(menu.getDataPage()))
                .extracting(AdminMenu::getName).containsOnly("menu.security.events");
    }

    @Test
    @DisplayName("an existing installation keeps the AI monitor's old menus off: their addresses open the console")
    void anExistingInstallationTurnsTheOldMenusOff() {
        AdminMenuService service = new AdminMenuService(menuRepository, menuQueryCache, false, false);
        AdminMenu oldOverview = AdminMenu.builder().name("menu.aiMonitor.overview").url("/contexa/admin/ai-monitor")
                .dataPage("ai-monitor-overview").enabled(true).build();
        oldOverview.setId(40L);
        when(menuRepository.count()).thenReturn(30L);
        when(menuRepository.findDuplicatedDataPages()).thenReturn(Collections.emptyList());
        when(menuRepository.findAllByDataPageOrderByIdAsc(anyString())).thenReturn(Collections.emptyList());
        when(menuRepository.findAllByDataPageOrderByIdAsc("ai-monitor-overview")).thenReturn(List.of(oldOverview));
        when(menuRepository.save(any(AdminMenu.class))).thenAnswer(inv -> {
            AdminMenu menu = inv.getArgument(0);
            if (menu.getId() == null) {
                menu.setId(1L);
            }
            return menu;
        });

        service.initializeDefaultMenusIfEmpty();

        assertThat(oldOverview.isEnabled()).isFalse();
        verify(menuRepository).save(oldOverview);
    }

    @Nested
    @DisplayName("deduplicateMenusByDataPage")
    class DeduplicateMenus {

        @Test
        @DisplayName("should merge roles and delete duplicates")
        void success() {
            AdminMenuService service = new AdminMenuService(menuRepository, menuQueryCache, false, false);
            when(menuRepository.count()).thenReturn(5L);
            when(menuRepository.findDuplicatedDataPages())
                    .thenReturn(List.of("dup-page"), Collections.emptyList());
            when(menuRepository.findAllByDataPageOrderByIdAsc(anyString())).thenReturn(Collections.emptyList());
            when(menuRepository.save(any(AdminMenu.class))).thenAnswer(inv -> {
                AdminMenu menu = inv.getArgument(0);
                if (menu.getId() == null) {
                    menu.setId(100L);
                }
                return menu;
            });

            AdminMenu menu1 = AdminMenu.builder().id(10L).dataPage("dup-page").build();
            menu1.addRole("ROLE_USER");
            AdminMenu menu2 = AdminMenu.builder().id(11L).dataPage("dup-page").build();
            menu2.addRole("ROLE_ADMIN");

            when(menuRepository.findAllByDataPageOrderByIdAsc("dup-page")).thenReturn(List.of(menu1, menu2));

            service.initializeDefaultMenusIfEmpty(); // triggers deduplicate

            verify(menuRepository).reassignChildren(11L, 10L);
            verify(menuRepository).deleteById(11L);
            verify(menuRepository).save(menu1);
            assertThat(menu1.getRoles()).extracting(AdminMenuRole::getRoleName).containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
        }
    }

    @Nested
    @DisplayName("getMenuTreeForUser")
    class GetMenuTree {

        @Test
        @DisplayName("should filter core, enterprise and saas based on feature flags and roles")
        void testFilterAndTreeBuilding() {
            AdminMenuService service = new AdminMenuService(menuRepository, menuQueryCache, true, false); // Enterprise enabled, Saas disabled

            AdminMenu m1 = AdminMenu.builder().id(1L).name("Core").menuType("CORE").enabled(true).build();
            AdminMenu m2 = AdminMenu.builder().id(2L).name("Enterprise").menuType("ENTERPRISE").enabled(true).build();
            AdminMenu m3 = AdminMenu.builder().id(3L).name("Saas").menuType("SAAS").enabled(true).build();
            AdminMenu m4 = AdminMenu.builder().id(4L).name("DisabledCore").menuType("CORE").enabled(false).build();
            AdminMenu m5 = AdminMenu.builder().id(5L).name("ChildOfCore").parentId(1L).menuType("CORE").enabled(true).build();

            // Setup role constraint on m2
            m2.addRole("ROLE_ADMIN");

            when(menuQueryCache.findAllWithRoles()).thenReturn(List.of(m1, m2, m3, m4, m5));

            // User has ROLE_USER only (can't access m2)
            List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
            List<AdminMenuService.MenuNode> tree = service.getMenuTreeForUser(authorities);

            // Output should have m1, and its child m5. m2 is excluded due to role, m3 due to saas feature flag, m4 because it's disabled.
            assertThat(tree).hasSize(1);
            assertThat(tree.get(0).name()).isEqualTo("Core");
            assertThat(tree.get(0).children()).hasSize(1);
            assertThat(tree.get(0).children().get(0).name()).isEqualTo("ChildOfCore");
        }
    }

    @Test
    @DisplayName("toggleEnabled should toggle and save")
    void toggleEnabled() {
        AdminMenuService service = new AdminMenuService(menuRepository, menuQueryCache, false, false);
        AdminMenu menu = AdminMenu.builder().id(1L).enabled(true).build();
        when(menuRepository.findById(1L)).thenReturn(Optional.of(menu));

        service.toggleEnabled(1L);

        assertThat(menu.isEnabled()).isFalse();
        verify(menuRepository).save(menu);
        verify(menuQueryCache).invalidate();
    }

    @Test
    @DisplayName("updateMenuRoles should clear and save new roles")
    void updateMenuRoles() {
        AdminMenuService service = new AdminMenuService(menuRepository, menuQueryCache, false, false);
        AdminMenu menu = AdminMenu.builder().id(1L).build();
        menu.addRole("ROLE_OLD");
        when(menuRepository.findById(1L)).thenReturn(Optional.of(menu));

        service.updateMenuRoles(1L, Set.of("ROLE_NEW1", "ROLE_NEW2"));

        verify(menuRepository).save(menu);
        verify(menuQueryCache).invalidate();
        assertThat(menu.getRoles()).extracting(AdminMenuRole::getRoleName).containsExactlyInAnyOrder("ROLE_NEW1", "ROLE_NEW2");
    }

    @Test
    @DisplayName("a stored icon of no known form stays out of the menu tree")
    void aStoredIconOfNoKnownFormStaysOutOfTheTree() {
        AdminMenuService service = new AdminMenuService(menuRepository, menuQueryCache, false, false);
        AdminMenu menu = AdminMenu.builder().id(1L).name("Custom").icon("<b>Sales & Ops</b>").enabled(true).build();
        when(menuQueryCache.findAllWithRoles()).thenReturn(List.of(menu));

        assertThat(service.getMenuTreeForUser(List.of())).extracting(AdminMenuService.MenuNode::icon).containsExactly("");
    }

    @Test
    @DisplayName("a stored address that may leave the application is no link in the menu tree")
    void aStoredAddressOutsideTheApplicationIsNoLink() {
        AdminMenuService service = new AdminMenuService(menuRepository, menuQueryCache, false, false);
        AdminMenu script = AdminMenu.builder().id(1L).name("Script").url("javascript:alert(1)").enabled(true).build();
        AdminMenu elsewhere = AdminMenu.builder().id(2L).name("Elsewhere").url("//evil.example/").enabled(true).build();
        AdminMenu inside = AdminMenu.builder().id(3L).name("Inside").url("/contexa/admin/users").enabled(true).build();
        when(menuQueryCache.findAllWithRoles()).thenReturn(List.of(script, elsewhere, inside));

        assertThat(service.getMenuTreeForUser(List.of())).extracting(AdminMenuService.MenuNode::url)
                .containsExactly(null, null, "/contexa/admin/users");
    }

    @Test
    @DisplayName("deleteMenu should delete children and parent")
    void deleteMenu() {
        AdminMenuService service = new AdminMenuService(menuRepository, menuQueryCache, false, false);
        AdminMenu child = AdminMenu.builder().id(11L).name("Child").parentId(10L).build();
        AdminMenu grandchild = AdminMenu.builder().id(12L).name("Grandchild").parentId(11L).build();
        when(menuRepository.findByParentIdOrderByMenuOrderAsc(10L)).thenReturn(List.of(child));
        when(menuRepository.findByParentIdOrderByMenuOrderAsc(11L)).thenReturn(List.of(grandchild));
        when(menuRepository.findByParentIdOrderByMenuOrderAsc(12L)).thenReturn(List.of());

        service.deleteMenu(10L);

        // Every level goes, the deepest first, so no submenu is left pointing at a parent that is gone.
        verify(menuRepository).deleteAll(List.of(grandchild, child));
        verify(menuRepository).deleteById(10L);
        verify(menuQueryCache).invalidate();
    }
}
