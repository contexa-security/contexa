package io.contexa.contexaiam.admin.web.menu.controller;

import io.contexa.contexacommon.entity.AdminMenu;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexaiam.admin.web.menu.service.AdminMenuService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/admin/menu-management")
@RequiredArgsConstructor
public class AdminMenuController {

    private final AdminMenuService adminMenuService;
    private final RoleRepository roleRepository;

    @GetMapping
    public String menuManagement(Model model) {
        List<AdminMenu> menus = adminMenuService.getAllMenus();
        List<AdminMenu> sorted = sortParentThenChildren(menus);
        Set<Long> parentIds = menus.stream()
                .map(AdminMenu::getParentId)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
        model.addAttribute("activePage", "menu-management");
        model.addAttribute("menus", sorted);
        model.addAttribute("parentIds", parentIds);
        model.addAttribute("allRoles", roleRepository.findAll());
        return "admin/menu-management";
    }

    private List<AdminMenu> sortParentThenChildren(List<AdminMenu> menus) {
        List<AdminMenu> parents = menus.stream()
                .filter(m -> m.getParentId() == null)
                .sorted(Comparator.comparingInt(AdminMenu::getMenuOrder))
                .toList();
        List<AdminMenu> sorted = new ArrayList<>();
        for (AdminMenu parent : parents) {
            sorted.add(parent);
            menus.stream()
                    .filter(m -> parent.getId().equals(m.getParentId()))
                    .sorted(Comparator.comparingInt(AdminMenu::getMenuOrder))
                    .forEach(sorted::add);
        }
        return sorted;
    }

    @PostMapping("/api/toggle/{id}")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> toggleMenu(@PathVariable Long id) {
        adminMenuService.toggleEnabled(id);
        return ResponseEntity.ok(Map.of("success", true));
    }

    @PostMapping("/api/roles/{id}")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> updateRoles(@PathVariable Long id,
                                                            @RequestBody Map<String, List<String>> body) {
        Set<String> roles = body.getOrDefault("roles", List.of()).stream().collect(Collectors.toSet());
        adminMenuService.updateMenuRoles(id, roles);
        return ResponseEntity.ok(Map.of("success", true));
    }

    @PostMapping("/api/order")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> updateOrder(@RequestBody List<Map<String, Object>> orders) {
        for (Map<String, Object> item : orders) {
            Long menuId = Long.valueOf(item.get("id").toString());
            int order = Integer.parseInt(item.get("order").toString());
            adminMenuService.updateMenuOrder(menuId, order);
        }
        return ResponseEntity.ok(Map.of("success", true));
    }

    @PostMapping("/api/create")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> createMenu(@RequestBody Map<String, String> body) {
        AdminMenu menu = new AdminMenu();
        menu.setName(body.getOrDefault("name", ""));
        menu.setUrl(body.get("url"));
        menu.setIcon(body.getOrDefault("icon", ""));
        menu.setDataPage(body.get("dataPage"));
        menu.setMenuType(body.getOrDefault("menuType", "CORE"));
        String parentId = body.get("parentId");
        if (parentId != null && !parentId.isBlank()) {
            menu.setParentId(Long.valueOf(parentId));
        }
        menu.setMenuOrder(Integer.parseInt(body.getOrDefault("menuOrder", "0")));
        if (body.containsKey("enabled")) {
            menu.setEnabled(Boolean.parseBoolean(body.get("enabled")));
        }
        adminMenuService.saveMenu(menu);
        return ResponseEntity.ok(Map.of("success", true, "id", menu.getId()));
    }

    @PutMapping("/api/{id}")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> updateMenu(@PathVariable Long id, @RequestBody Map<String, String> body) {
        return adminMenuService.getMenuById(id).map(menu -> {
            if (body.containsKey("name")) menu.setName(body.get("name"));
            if (body.containsKey("url")) menu.setUrl(body.get("url"));
            if (body.containsKey("icon")) menu.setIcon(body.get("icon"));
            if (body.containsKey("dataPage")) menu.setDataPage(body.get("dataPage"));
            if (body.containsKey("menuType")) menu.setMenuType(body.get("menuType"));
            if (body.containsKey("menuOrder")) menu.setMenuOrder(Integer.parseInt(body.get("menuOrder")));
            if (body.containsKey("enabled")) menu.setEnabled(Boolean.parseBoolean(body.get("enabled")));
            String parentId = body.get("parentId");
            menu.setParentId(parentId != null && !parentId.isBlank() ? Long.valueOf(parentId) : null);
            adminMenuService.saveMenu(menu);
            Map<String, Object> result = new java.util.LinkedHashMap<>();
            result.put("success", true);
            return ResponseEntity.ok(result);
        }).orElseGet(() -> {
            Map<String, Object> err = new java.util.LinkedHashMap<>();
            err.put("success", false);
            err.put("error", "Menu not found");
            return ResponseEntity.badRequest().body(err);
        });
    }

    @DeleteMapping("/api/{id}")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> deleteMenu(@PathVariable Long id) {
        return adminMenuService.getMenuById(id).map(menu -> {
            if (menu.getName() != null && menu.getName().startsWith("menu.")) {
                return ResponseEntity.badRequest().body(Map.of("success", (Object) false, "error", (Object) "System menu cannot be deleted"));
            }
            adminMenuService.deleteMenu(id);
            return ResponseEntity.ok(Map.<String, Object>of("success", true));
        }).orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/api/{id}")
    @ResponseBody
    public ResponseEntity<?> getMenu(@PathVariable Long id) {
        return adminMenuService.getMenuById(id)
                .map(menu -> {
                    Map<String, Object> data = new java.util.LinkedHashMap<>();
                    data.put("id", menu.getId());
                    data.put("name", menu.getName());
                    data.put("url", menu.getUrl());
                    data.put("icon", menu.getIcon());
                    data.put("parentId", menu.getParentId());
                    data.put("menuOrder", menu.getMenuOrder());
                    data.put("menuType", menu.getMenuType());
                    data.put("dataPage", menu.getDataPage());
                    data.put("enabled", menu.isEnabled());
                    data.put("roles", menu.getRoles().stream().map(r -> r.getRoleName()).toList());
                    return ResponseEntity.ok(data);
                })
                .orElse(ResponseEntity.notFound().build());
    }
}
