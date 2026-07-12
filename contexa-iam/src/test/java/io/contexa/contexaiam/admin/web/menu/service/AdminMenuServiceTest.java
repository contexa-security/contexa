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
    @DisplayName("deleteMenu should delete children and parent")
    void deleteMenu() {
        AdminMenuService service = new AdminMenuService(menuRepository, menuQueryCache, false, false);

        service.deleteMenu(10L);

        verify(menuRepository).deleteByParentId(10L);
        verify(menuRepository).deleteById(10L);
        verify(menuQueryCache).invalidate();
    }
}
