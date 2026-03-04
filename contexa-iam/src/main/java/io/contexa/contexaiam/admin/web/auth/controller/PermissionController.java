package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexaiam.domain.entity.FunctionCatalog; 
import io.contexa.contexaiam.admin.web.metadata.service.FunctionCatalogService; 
import io.contexa.contexacommon.entity.Permission;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

@Controller
@RequestMapping("/admin/permissions")
@RequiredArgsConstructor
@Slf4j
public class PermissionController {

    private final PermissionService permissionService;
    private final ModelMapper modelMapper;
    private final FunctionCatalogService functionCatalogService;

    @GetMapping
    public String getPermissions(Model model) {
        List<Permission> permissions = permissionService.getAllPermissions();
        List<PermissionDto> dtoList = permissions.stream()
                .map(this::convertToDto)
                .toList();
        model.addAttribute("permissions", dtoList);
        return "admin/permissions";
    }

    @GetMapping("/register")
    public String registerPermissionForm(Model model) {
        model.addAttribute("permission", new PermissionDto());
        
        return "admin/permissiondetails";
    }

    @PostMapping
    public String createPermission(@ModelAttribute("permission") PermissionDto permissionDto, RedirectAttributes ra) {
        Permission permission = modelMapper.map(permissionDto, Permission.class);
        permissionService.createPermission(permission);
        ra.addFlashAttribute("message", "Permission '" + permission.getName() + "' has been successfully created.");
        return "redirect:/admin/permissions";
    }

    @GetMapping("/{id}")
    public String permissionDetails(@PathVariable Long id, Model model) {
        Permission permission = permissionService.getPermission(id)
                .orElseThrow(() -> new IllegalArgumentException("Invalid permission ID: " + id));

        PermissionDto permissionDto = convertToDto(permission);
        model.addAttribute("permission", permissionDto);
        
        return "admin/permissiondetails";
    }

    @PostMapping("/{id}/edit")
    public String updatePermission(@PathVariable Long id, @ModelAttribute("permission") PermissionDto permissionDto,
                                   RedirectAttributes ra) {
        Permission permission = permissionService.updatePermission(id, permissionDto);
        ra.addFlashAttribute("message", "Permission '" + permission.getName() + "' has been successfully updated.");
        return "redirect:/admin/permissions";
    }

    private void addCommonAttributesToModel(Model model) {
        List<FunctionCatalog> allActiveFunctions = functionCatalogService.findAllActiveFunctions();
        model.addAttribute("allFunctions", allActiveFunctions);
    }

    @PostMapping("/delete/{id}")
    public String deletePermission(@PathVariable Long id, RedirectAttributes ra) {
        try {
            permissionService.deletePermission(id);
            ra.addFlashAttribute("message", "Permission (ID: " + id + ") has been successfully deleted.");
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "Error occurred while deleting permission: " + e.getMessage());
        }
        return "redirect:/admin/permissions";
    }

    private PermissionDto convertToDto(Permission permission) {
        PermissionDto dto = modelMapper.map(permission, PermissionDto.class);
        if (permission.getManagedResource() != null) {
            dto.setManagedResourceId(permission.getManagedResource().getId());
            dto.setManagedResourceIdentifier(permission.getManagedResource().getResourceIdentifier());
        }
        return dto;
    }
}