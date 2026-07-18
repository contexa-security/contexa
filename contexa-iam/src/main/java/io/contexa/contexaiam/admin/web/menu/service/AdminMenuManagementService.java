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

import java.util.Objects;

import io.contexa.contexacommon.entity.AdminMenu;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexaiam.admin.web.menu.dto.AdminMenuDtos.AdminMenuActionResponse;
import io.contexa.contexaiam.admin.web.menu.dto.AdminMenuDtos.AdminMenuOrderRequest;
import io.contexa.contexaiam.admin.web.menu.dto.AdminMenuDtos.AdminMenuPageModel;
import io.contexa.contexaiam.admin.web.menu.dto.AdminMenuDtos.AdminMenuResponse;
import io.contexa.contexaiam.admin.web.menu.dto.AdminMenuDtos.AdminMenuRoleView;
import io.contexa.contexaiam.admin.web.menu.dto.AdminMenuDtos.AdminMenuRolesRequest;
import io.contexa.contexaiam.admin.web.menu.dto.AdminMenuDtos.AdminMenuSaveRequest;
import io.contexa.contexaiam.admin.web.menu.dto.AdminMenuDtos.AdminMenuView;
import io.contexa.contexaiam.admin.web.menu.dto.AdminMenuDtos.AdminRoleOptionView;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
public class AdminMenuManagementService {

    private final AdminMenuService adminMenuService;
    private final RoleRepository roleRepository;
    private final MessageSource messageSource;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    public AdminMenuPageModel getPageModel() {
        List<AdminMenu> menus = adminMenuService.getAllMenus();
        List<AdminMenuView> sorted = sortParentThenChildren(menus).stream()
                .map(this::toView)
                .toList();
        Set<Long> parentIds = menus.stream()
                .map(AdminMenu::getParentId)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
        List<AdminRoleOptionView> allRoles = roleRepository.findAll().stream()
                .map(role -> new AdminRoleOptionView(role.getRoleName()))
                .toList();
        return new AdminMenuPageModel(sorted, parentIds, allRoles);
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public AdminMenuActionResponse toggleMenu(Long id) {
        adminMenuService.toggleEnabled(id);
        return AdminMenuActionResponse.ok();
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public AdminMenuActionResponse updateRoles(Long id, AdminMenuRolesRequest request) {
        Set<String> roles = request.rolesOrEmpty().stream().collect(Collectors.toSet());
        adminMenuService.updateMenuRoles(id, roles);
        return AdminMenuActionResponse.ok();
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public AdminMenuActionResponse updateOrder(List<AdminMenuOrderRequest> orders) {
        List<AdminMenuOrderUpdate> updates = orders == null
                ? List.of()
                : orders.stream()
                .map(item -> new AdminMenuOrderUpdate(item.menuId(), item.menuOrder()))
                .toList();
        for (AdminMenuOrderUpdate item : updates) {
            adminMenuService.updateMenuOrder(item.menuId(), item.menuOrder());
        }
        return AdminMenuActionResponse.ok();
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public AdminMenuActionResponse createMenu(AdminMenuSaveRequest request) {
        AdminMenu menu = new AdminMenu();
        menu.setName(request.valueOrDefault("name", ""));
        menu.setUrl(request.getUrl());
        menu.setIcon(request.valueOrDefault("icon", ""));
        menu.setDataPage(request.getDataPage());
        menu.setMenuType(request.valueOrDefault("menuType", "CORE"));
        menu.setParentId(request.parentIdAsLong());
        menu.setMenuOrder(request.menuOrderOrDefault(0));
        if (request.has("enabled")) {
            menu.setEnabled(Boolean.parseBoolean(request.getEnabled()));
        }
        adminMenuService.saveMenu(menu);
        return AdminMenuActionResponse.created(menu.getId());
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public AdminMenuActionResponse updateMenu(Long id, AdminMenuSaveRequest request) {
        Optional<AdminMenu> existingMenu = adminMenuService.getMenuById(id);
        if (existingMenu.isEmpty()) {
            return AdminMenuActionResponse.error(msg("msg.menu.not.found"));
        }

        AdminMenu menu = existingMenu.get();
        if (request.has("name")) menu.setName(request.getName());
        if (request.has("url")) menu.setUrl(request.getUrl());
        if (request.has("icon")) menu.setIcon(request.getIcon());
        if (request.has("dataPage")) menu.setDataPage(request.getDataPage());
        if (request.has("menuType")) menu.setMenuType(request.getMenuType());
        if (request.has("menuOrder")) menu.setMenuOrder(request.menuOrderAsInt());
        if (request.has("enabled")) menu.setEnabled(Boolean.parseBoolean(request.getEnabled()));
        menu.setParentId(request.parentIdAsLong());
        adminMenuService.saveMenu(menu);
        return AdminMenuActionResponse.ok();
    }

    private record AdminMenuOrderUpdate(Long menuId, int menuOrder) {
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public Optional<AdminMenuActionResponse> deleteMenu(Long id) {
        return adminMenuService.getMenuById(id).map(menu -> {
            if (menu.getName() != null && menu.getName().startsWith("menu.")) {
                return AdminMenuActionResponse.error(msg("msg.menu.system.cannot.delete"));
            }
            adminMenuService.deleteMenu(id);
            return AdminMenuActionResponse.ok();
        });
    }

    public Optional<AdminMenuResponse> getMenu(Long id) {
        return adminMenuService.getMenuById(id).map(this::toResponse);
    }

    private List<AdminMenu> sortParentThenChildren(List<AdminMenu> menus) {
        Map<Long, List<AdminMenu>> childrenByParentId = new HashMap<>();
        for (AdminMenu menu : menus) {
            if (menu.getParentId() != null) {
                childrenByParentId
                        .computeIfAbsent(menu.getParentId(), ignored -> new ArrayList<>())
                        .add(menu);
            }
        }

        Set<AdminMenu> emitted = Collections.newSetFromMap(new IdentityHashMap<>());
        List<AdminMenu> sorted = new ArrayList<>();
        List<AdminMenu> parents = menus.stream()
                .filter(m -> m.getParentId() == null)
                .sorted(Comparator.comparingInt(AdminMenu::getMenuOrder))
                .toList();
        for (AdminMenu parent : parents) {
            appendMenuWithChildren(parent, childrenByParentId, emitted, sorted);
        }
        menus.stream()
                .filter(menu -> !emitted.contains(menu))
                .sorted(Comparator.comparingInt(AdminMenu::getMenuOrder))
                .forEach(menu -> appendMenuWithChildren(menu, childrenByParentId, emitted, sorted));
        return sorted;
    }

    private void appendMenuWithChildren(
            AdminMenu menu,
            Map<Long, List<AdminMenu>> childrenByParentId,
            Set<AdminMenu> emitted,
            List<AdminMenu> sorted) {
        if (!emitted.add(menu)) {
            return;
        }
        sorted.add(menu);
        if (menu.getId() == null) {
            return;
        }
        childrenByParentId.getOrDefault(menu.getId(), List.of()).stream()
                .sorted(Comparator.comparingInt(AdminMenu::getMenuOrder))
                .forEach(child -> appendMenuWithChildren(child, childrenByParentId, emitted, sorted));
    }

    private AdminMenuView toView(AdminMenu menu) {
        return new AdminMenuView(
                menu.getId(),
                menu.getName(),
                menu.getUrl(),
                menu.getIcon(),
                menu.getParentId(),
                menu.getMenuOrder(),
                menu.isEnabled(),
                menu.getMenuType(),
                menu.getDataPage(),
                menu.getRoles().stream()
                        .map(role -> new AdminMenuRoleView(role.getRoleName()))
                        .toList()
        );
    }

    private AdminMenuResponse toResponse(AdminMenu menu) {
        return new AdminMenuResponse(
                menu.getId(),
                menu.getName(),
                menu.getUrl(),
                menu.getIcon(),
                menu.getParentId(),
                menu.getMenuOrder(),
                menu.getMenuType(),
                menu.getDataPage(),
                menu.isEnabled(),
                menu.getRoles().stream().map(r -> r.getRoleName()).toList()
        );
    }
}
