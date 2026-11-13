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
import io.contexa.contexaiam.admin.web.menu.dto.AdminMenuIcon;
import io.contexa.contexaiam.admin.web.menu.dto.AdminMenuUrl;
import io.contexa.contexaiam.common.ConsoleInput;
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
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
public class AdminMenuManagementService {

    private final AdminMenuService adminMenuService;
    private final RoleRepository roleRepository;
    private final MessageSource messageSource;

    /** The kinds of menu the side menu shows by the edition. */
    private static final Set<String> MENU_TYPES = Set.of("CORE", "ENTERPRISE", "SAAS");

    /** How the name of a built-in menu begins: it is the message key of its label, set by the seed. */
    private static final String SYSTEM_NAME_PREFIX = "menu.";

    /** By the order, then by the id: two menus of the same order keep one place whatever the database returns first. */
    private static final Comparator<AdminMenu> MENU_ORDER = Comparator.comparingInt(AdminMenu::getMenuOrder)
            .thenComparing(AdminMenu::getId, Comparator.nullsLast(Comparator.naturalOrder()));

    /** The lengths of the columns of a menu. */
    private static final int NAME_LENGTH = 100;
    private static final int DATA_PAGE_LENGTH = 50;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    /**
     * Whether the menu is one of the console's own. Its name, a message key, and its data page, the key the seed finds it
     * by at every start, cannot be changed, so the mark cannot be taken off it.
     */
    static boolean isSystemMenu(AdminMenu menu) {
        return menu.getName() != null && menu.getName().startsWith(SYSTEM_NAME_PREFIX);
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
        String name = ConsoleInput.required(messageSource, "crud.field.menu.name", request.getName(), NAME_LENGTH);
        requireOwnName(name);
        String icon = request.valueOrDefault("icon", "");
        requireAllowedIcon(icon);
        requireAllowedUrl(request.getUrl());
        String dataPage = ConsoleInput.optional(messageSource, "crud.field.menu.data.page", request.getDataPage(),
                DATA_PAGE_LENGTH);
        requireFreeDataPage(dataPage, null);
        Long parentId = request.parentIdAsLong();
        requireAllowedParent(parentId, null);
        AdminMenu menu = new AdminMenu();
        menu.setName(name);
        menu.setUrl(request.getUrl());
        menu.setIcon(icon);
        menu.setDataPage(dataPage);
        menu.setMenuType(menuType(request.valueOrDefault("menuType", "CORE")));
        menu.setParentId(parentId);
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

        if (request.has("icon")) {
            requireAllowedIcon(request.getIcon());
        }
        if (request.has("url")) {
            requireAllowedUrl(request.getUrl());
        }
        AdminMenu menu = existingMenu.get();
        boolean system = isSystemMenu(menu);
        if (request.has("name")) {
            String name = ConsoleInput.required(messageSource, "crud.field.menu.name", request.getName(), NAME_LENGTH);
            if (!name.equals(menu.getName())) {
                requireUnlocked(system);
                requireOwnName(name);
            }
            menu.setName(name);
        }
        if (request.has("dataPage")) {
            String dataPage = ConsoleInput.optional(messageSource, "crud.field.menu.data.page", request.getDataPage(),
                    DATA_PAGE_LENGTH);
            if (!Objects.equals(dataPage, menu.getDataPage())) {
                requireUnlocked(system);
                requireFreeDataPage(dataPage, menu.getId());
            }
            menu.setDataPage(dataPage);
        }
        if (request.has("url")) menu.setUrl(request.getUrl());
        if (request.has("icon")) menu.setIcon(request.getIcon());
        if (request.has("menuType")) menu.setMenuType(menuType(request.getMenuType()));
        if (request.has("menuOrder")) menu.setMenuOrder(request.menuOrderAsInt());
        if (request.has("enabled")) menu.setEnabled(Boolean.parseBoolean(request.getEnabled()));
        // A request that names no parent keeps the parent; one that sends an empty or null parent makes a top menu.
        if (request.has("parentId")) {
            Long parentId = request.parentIdAsLong();
            if (!Objects.equals(parentId, menu.getParentId())) {
                requireAllowedParent(parentId, menu);
            }
            menu.setParentId(parentId);
        }
        adminMenuService.saveMenu(menu);
        return AdminMenuActionResponse.ok();
    }

    /** A name that begins as a built-in menu's would make the menu one: it could no longer be renamed or deleted. */
    private void requireOwnName(String name) {
        if (name.startsWith(SYSTEM_NAME_PREFIX)) {
            throw new IllegalArgumentException(msg("msg.menu.name.reserved", SYSTEM_NAME_PREFIX));
        }
    }

    /** The name and data page of a built-in menu stay: the seed would add the menu again under its data page. */
    private void requireUnlocked(boolean system) {
        if (system) {
            throw new IllegalArgumentException(msg("msg.menu.system.locked"));
        }
    }

    /** The data page is the key a menu is found by: two menus under one would both be shown as the same page. */
    private void requireFreeDataPage(String dataPage, Long ownId) {
        if (dataPage == null) {
            return;
        }
        boolean taken = adminMenuService.getMenusByDataPage(dataPage).stream()
                .anyMatch(other -> !Objects.equals(other.getId(), ownId));
        if (taken) {
            throw new IllegalArgumentException(msg("msg.menu.data.page.duplicate", dataPage));
        }
    }

    /**
     * The side menu has two levels: a parent is a top menu that exists and is not the menu itself, and a menu that has
     * submenus stays a top menu.
     */
    private void requireAllowedParent(Long parentId, AdminMenu menu) {
        if (parentId == null) {
            return;
        }
        boolean allowed = (menu == null || !parentId.equals(menu.getId()))
                && adminMenuService.getMenuById(parentId).filter(parent -> parent.getParentId() == null).isPresent()
                && (menu == null || adminMenuService.getDescendants(menu.getId()).isEmpty());
        if (!allowed) {
            throw new IllegalArgumentException(msg("msg.menu.parent.invalid"));
        }
    }

    private String menuType(String requested) {
        String type = requested == null ? "" : requested.trim().toUpperCase(Locale.ROOT);
        if (!MENU_TYPES.contains(type)) {
            throw new IllegalArgumentException(msg("msg.menu.type.invalid"));
        }
        return type;
    }

    /** An icon that opens with a tag reaches every administrator's page as markup, so only a plain drawing is kept. */
    private void requireAllowedIcon(String icon) {
        if (!AdminMenuIcon.isAllowed(icon)) {
            throw new IllegalArgumentException(msg("msg.menu.icon.invalid"));
        }
    }

    /** The address becomes the link of every administrator's side menu, so only a path inside this application is kept. */
    private void requireAllowedUrl(String url) {
        if (!AdminMenuUrl.isAllowed(url)) {
            throw new IllegalArgumentException(msg("msg.menu.url.invalid"));
        }
    }

    private record AdminMenuOrderUpdate(Long menuId, int menuOrder) {
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public Optional<AdminMenuActionResponse> deleteMenu(Long id) {
        return adminMenuService.getMenuById(id).map(menu -> {
            if (isSystemMenu(menu)) {
                return AdminMenuActionResponse.error(msg("msg.menu.system.cannot.delete"));
            }
            // The submenus go with the menu, down to the last level; a built-in one among them keeps it.
            List<String> builtIn = adminMenuService.getDescendants(id).stream()
                    .filter(AdminMenuManagementService::isSystemMenu)
                    .map(AdminMenu::getName)
                    .toList();
            if (!builtIn.isEmpty()) {
                return AdminMenuActionResponse.error(msg("msg.menu.system.child.cannot.delete",
                        builtIn.stream().map(name -> messageSource.getMessage(name, null, name,
                                LocaleContextHolder.getLocale())).collect(Collectors.joining(", "))));
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
                .sorted(MENU_ORDER)
                .toList();
        for (AdminMenu parent : parents) {
            appendMenuWithChildren(parent, childrenByParentId, emitted, sorted);
        }
        menus.stream()
                .filter(menu -> !emitted.contains(menu))
                .sorted(MENU_ORDER)
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
                .sorted(MENU_ORDER)
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
