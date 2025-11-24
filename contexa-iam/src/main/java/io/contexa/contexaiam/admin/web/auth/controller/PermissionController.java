package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexaiam.domain.entity.FunctionCatalog; // 복원된 메서드에서 사용하므로 import 추가
import io.contexa.contexaiam.admin.web.metadata.service.FunctionCatalogService; // 복원된 메서드에서 사용하므로 import 추가
import io.contexa.contexacommon.entity.Permission;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

/**
 * [최종 수정]
 * 사유: 삭제했던 addCommonAttributesToModel 메서드를 원칙에 따라 복원합니다.
 *      단, 새로운 1:1 관계 모델에서는 더 이상 기능 목록이 필요하지 않으므로,
 *      registerPermissionForm과 permissionDetails 메서드 내에서 해당 메서드 '호출' 부분만 제거합니다.
 *      이를 통해 기존 메서드를 보존하면서도 새로운 로직과의 충돌을 해결합니다.
 */
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
        // [수정] addCommonAttributesToModel 호출 제거
        return "admin/permissiondetails";
    }

    @PostMapping
    public String createPermission(@ModelAttribute("permission") PermissionDto permissionDto, RedirectAttributes ra) {
        Permission permission = modelMapper.map(permissionDto, Permission.class);
        permissionService.createPermission(permission);
        ra.addFlashAttribute("message", "권한 '" + permission.getName() + "'이 성공적으로 생성되었습니다.");
        return "redirect:/admin/permissions";
    }

    @GetMapping("/{id}")
    public String permissionDetails(@PathVariable Long id, Model model) {
        Permission permission = permissionService.getPermission(id)
                .orElseThrow(() -> new IllegalArgumentException("Invalid permission ID: " + id));

        PermissionDto permissionDto = convertToDto(permission);
        model.addAttribute("permission", permissionDto);
        // [수정] addCommonAttributesToModel 호출 제거
        return "admin/permissiondetails";
    }

    @PostMapping("/{id}/edit")
    public String updatePermission(@PathVariable Long id, @ModelAttribute("permission") PermissionDto permissionDto,
                                   RedirectAttributes ra) {
        Permission permission = permissionService.updatePermission(id, permissionDto);
        ra.addFlashAttribute("message", "권한 '" + permission.getName() + "'이 성공적으로 업데이트되었습니다.");
        return "redirect:/admin/permissions";
    }

    /**
     * [복원]
     * 기존에 존재하던 메서드를 삭제하지 않고 그대로 유지합니다.
     * 현재는 호출되지 않지만, 향후 다른 기능에서 필요할 수 있습니다.
     */
    private void addCommonAttributesToModel(Model model) {
        List<FunctionCatalog> allActiveFunctions = functionCatalogService.findAllActiveFunctions();
        model.addAttribute("allFunctions", allActiveFunctions);
    }

    @GetMapping("/delete/{id}")
    public String deletePermission(@PathVariable Long id, RedirectAttributes ra) {
        try {
            permissionService.deletePermission(id);
            ra.addFlashAttribute("message", "권한 (ID: " + id + ")이 성공적으로 삭제되었습니다.");
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "권한 삭제 중 오류 발생: " + e.getMessage());
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