package io.contexa.contexaiam.admin.web.metadata.controller;

import io.contexa.contexaiam.domain.dto.ResourceManagementDto;
import io.contexa.contexaiam.domain.dto.ResourceMetadataDto;
import io.contexa.contexaiam.domain.dto.ResourceSearchCriteria;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.admin.web.workflow.wizard.service.PermissionWizardService;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Map;
import java.util.Set;

@RequestMapping("/admin/workbench/resources")
@RequiredArgsConstructor
@Slf4j
public class ResourceAdminController {

    private final ResourceRegistryService resourceRegistryService;
    private final PermissionWizardService permissionWizardService;

    @GetMapping
    public String resourceWorkbenchPage(
            @ModelAttribute("criteria") ResourceSearchCriteria criteria,
            @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable,
            Model model) {

        Page<ManagedResource> resourcePage = resourceRegistryService.findResources(criteria, pageable);
        Set<String> serviceOwners = resourceRegistryService.getAllServiceOwners();

        model.addAttribute("resourcePage", resourcePage);
        model.addAttribute("serviceOwners", serviceOwners);
        model.addAttribute("criteria", criteria);
        return "admin/resource-workbench";
    }

    @PostMapping("/refresh")
    public String refreshResources(RedirectAttributes ra) {
        try {
            resourceRegistryService.refreshAndSynchronizeResources();
            ra.addFlashAttribute("message", "시스템 리소스를 성공적으로 새로고침했습니다.");
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "리소스 새로고침 중 오류 발생: " + e.getMessage());
        }
        return "redirect:/admin/workbench/resources";
    }

    
    @PostMapping("/{id}/define")
    @ResponseBody 
    public ResponseEntity<Map<String, Object>> defineResourceAsPermissionApi(@PathVariable Long id, @ModelAttribute ResourceMetadataDto metadataDto) {
        try {
            
            Permission newPermission = resourceRegistryService.defineResourceAsPermission(id, metadataDto);

            
            Map<String, Object> response = Map.of(
                    "success", true,
                    "message", "리소스가 성공적으로 권한으로 정의되었습니다.",
                    "permissionId", newPermission.getId(),
                    "permissionName", newPermission.getFriendlyName()
            );
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("권한 정의 API 처리 중 오류 발생: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", e.getMessage()));
        }
    }

   

    @PostMapping("/{id}/exclude")
    public String excludeResource(@PathVariable Long id, RedirectAttributes ra) {
        try {
            resourceRegistryService.excludeResourceFromManagement(id);
            ra.addFlashAttribute("message", "리소스가 '관리 제외' 처리되었습니다.");
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "처리 중 오류 발생: " + e.getMessage());
        }
        return "redirect:/admin/workbench/resources";
    }

    @PostMapping("/{id}/manage")
    public String updateManagementStatus(@PathVariable Long id, @ModelAttribute ResourceManagementDto managementDto, RedirectAttributes ra) {
        try {
            resourceRegistryService.updateResourceManagementStatus(id, managementDto);
            ra.addFlashAttribute("message", "리소스 (ID: " + id + ")의 관리 상태가 변경되었습니다.");
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "관리 상태 변경 중 오류 발생: " + e.getMessage());
        }
        return "redirect:/admin/workbench/resources";
    }
}