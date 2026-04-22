package io.contexa.contexaiam.admin.web.menu.controller;

import io.contexa.contexaiam.admin.web.menu.dto.AdminMenuDtos.AdminMenuActionResponse;
import io.contexa.contexaiam.admin.web.menu.dto.AdminMenuDtos.AdminMenuOrderRequest;
import io.contexa.contexaiam.admin.web.menu.dto.AdminMenuDtos.AdminMenuPageModel;
import io.contexa.contexaiam.admin.web.menu.dto.AdminMenuDtos.AdminMenuResponse;
import io.contexa.contexaiam.admin.web.menu.dto.AdminMenuDtos.AdminMenuRolesRequest;
import io.contexa.contexaiam.admin.web.menu.dto.AdminMenuDtos.AdminMenuSaveRequest;
import io.contexa.contexaiam.admin.web.menu.service.AdminMenuManagementService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;

@Controller
@RequestMapping("/admin/menu-management")
@RequiredArgsConstructor
public class AdminMenuController {

    private final AdminMenuManagementService adminMenuManagementService;

    @GetMapping
    public String menuManagement(Model model) {
        AdminMenuPageModel pageModel = adminMenuManagementService.getPageModel();
        model.addAttribute("activePage", "menu-management");
        model.addAttribute("menus", pageModel.menus());
        model.addAttribute("parentIds", pageModel.parentIds());
        model.addAttribute("allRoles", pageModel.allRoles());
        return "admin/menu-management";
    }

    @PostMapping("/api/toggle/{id}")
    @ResponseBody
    public ResponseEntity<AdminMenuActionResponse> toggleMenu(@PathVariable Long id) {
        return ResponseEntity.ok(adminMenuManagementService.toggleMenu(id));
    }

    @PostMapping("/api/roles/{id}")
    @ResponseBody
    public ResponseEntity<AdminMenuActionResponse> updateRoles(
            @PathVariable Long id,
            @RequestBody AdminMenuRolesRequest request) {
        return ResponseEntity.ok(adminMenuManagementService.updateRoles(id, request));
    }

    @PostMapping("/api/order")
    @ResponseBody
    public ResponseEntity<AdminMenuActionResponse> updateOrder(@RequestBody List<AdminMenuOrderRequest> orders) {
        try {
            return ResponseEntity.ok(adminMenuManagementService.updateOrder(orders));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(AdminMenuActionResponse.error(e.getMessage()));
        }
    }

    @PostMapping("/api/create")
    @ResponseBody
    public ResponseEntity<AdminMenuActionResponse> createMenu(@RequestBody AdminMenuSaveRequest request) {
        try {
            return ResponseEntity.ok(adminMenuManagementService.createMenu(request));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(AdminMenuActionResponse.error(e.getMessage()));
        }
    }

    @PutMapping("/api/{id}")
    @ResponseBody
    public ResponseEntity<AdminMenuActionResponse> updateMenu(
            @PathVariable Long id,
            @RequestBody AdminMenuSaveRequest request) {
        AdminMenuActionResponse response;
        try {
            response = adminMenuManagementService.updateMenu(id, request);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(AdminMenuActionResponse.error(e.getMessage()));
        }
        if (!response.success()) {
            return ResponseEntity.badRequest().body(response);
        }
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/api/{id}")
    @ResponseBody
    public ResponseEntity<AdminMenuActionResponse> deleteMenu(@PathVariable Long id) {
        return adminMenuManagementService.deleteMenu(id)
                .map(response -> response.success()
                        ? ResponseEntity.ok(response)
                        : ResponseEntity.badRequest().body(response))
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/api/{id}")
    @ResponseBody
    public ResponseEntity<AdminMenuResponse> getMenu(@PathVariable Long id) {
        return adminMenuManagementService.getMenu(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }
}
