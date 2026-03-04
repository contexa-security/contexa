package io.contexa.contexaiam.admin.web.metadata.controller;

import io.contexa.contexaiam.domain.dto.ResourceManagementDto;
import io.contexa.contexaiam.domain.dto.ResourceMetadataDto;
import io.contexa.contexaiam.domain.dto.ResourceSearchCriteria;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
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

import org.springframework.stereotype.Controller;

@Controller
@RequestMapping("/admin/workbench/resources")
@RequiredArgsConstructor
@Slf4j
public class ResourceAdminController {

    private final ResourceRegistryService resourceRegistryService;

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
            ra.addFlashAttribute("message", "System resources have been successfully refreshed.");
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "Error occurred while refreshing resources: " + e.getMessage());
        }
        return "redirect:/admin/workbench/resources";
    }

    @PostMapping("/{id}/define")
    @ResponseBody 
    public ResponseEntity<Map<String, Object>> defineResourceAsPermissionApi(@PathVariable Long id, @ModelAttribute ResourceMetadataDto metadataDto) {
        try {
            
            Permission newPermission = resourceRegistryService.defineResourceAsPermission(id, metadataDto);

            Map<String, Object> response = Map.of(
                    "message", "Resource has been successfully defined as a permission.",
                    "permissionId", newPermission.getId(),
                    "permissionName", newPermission.getFriendlyName()
            );
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Permission definition API failed for resource ID: {}", id, e);
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/{id}/restore")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> restoreResource(@PathVariable Long id) {
        try {
            ResourceManagementDto dto = new ResourceManagementDto();
            dto.setStatus(ManagedResource.Status.NEEDS_DEFINITION);
            resourceRegistryService.updateResourceManagementStatus(id, dto);
            return ResponseEntity.ok(Map.of(
                    "message", "Resource restored to management",
                    "resourceId", id,
                    "newStatus", "NEEDS_DEFINITION"
            ));
        } catch (Exception e) {
            log.error("Resource restore failed for ID: {}", id, e);
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/{id}/exclude")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> excludeResource(@PathVariable Long id) {
        try {
            resourceRegistryService.excludeResourceFromManagement(id);
            return ResponseEntity.ok(Map.of(
                    "message", "Resource excluded from management",
                    "resourceId", id,
                    "newStatus", "EXCLUDED"
            ));
        } catch (Exception e) {
            log.error("Resource exclude failed for ID: {}", id, e);
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/{id}/manage")
    public String updateManagementStatus(@PathVariable Long id, @ModelAttribute ResourceManagementDto managementDto, RedirectAttributes ra) {
        try {
            resourceRegistryService.updateResourceManagementStatus(id, managementDto);
            ra.addFlashAttribute("message", "Management status of resource (ID: " + id + ") has been changed.");
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "Error occurred while changing management status: " + e.getMessage());
        }
        return "redirect:/admin/workbench/resources";
    }
}