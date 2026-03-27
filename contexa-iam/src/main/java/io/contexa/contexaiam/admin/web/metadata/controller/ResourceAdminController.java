package io.contexa.contexaiam.admin.web.metadata.controller;

import io.contexa.contexaiam.domain.dto.ResourceManagementDto;
import io.contexa.contexaiam.domain.dto.ResourceMetadataDto;
import io.contexa.contexaiam.domain.dto.ResourceSearchCriteria;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.*;

import org.springframework.stereotype.Controller;

@Controller
@RequestMapping("/admin/workbench/resources")
@RequiredArgsConstructor
@Slf4j
public class ResourceAdminController {

    private final ResourceRegistryService resourceRegistryService;
    private final ManagedResourceRepository managedResourceRepository;
    private final MessageSource messageSource;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @GetMapping
    public String resourceWorkbenchPage(
            @ModelAttribute("criteria") ResourceSearchCriteria criteria,
            @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable,
            Model model) {

        model.addAttribute("activePage", "policy-center");
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
            ra.addFlashAttribute("message", msg("msg.resource.refreshed"));
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", msg("msg.resource.refresh.error", e.getMessage()));
        }
        return "redirect:/admin/workbench/resources";
    }

    @PostMapping("/{id}/define")
    @ResponseBody 
    public ResponseEntity<Map<String, Object>> defineResourceAsPermissionApi(@PathVariable Long id, @ModelAttribute ResourceMetadataDto metadataDto) {
        try {
            
            Permission newPermission = resourceRegistryService.defineResourceAsPermission(id, metadataDto);

            Map<String, Object> response = Map.of(
                    "message", msg("msg.resource.permission.created"),
                    "permissionId", newPermission.getId(),
                    "permissionName", newPermission.getFriendlyName()
            );
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Permission definition API failed for resource ID: {}", id, e);
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/define-batch")
    @ResponseBody
    public ResponseEntity<List<Map<String, Object>>> defineResourcesBatch(@RequestBody List<Map<String, Object>> requests) {
        List<Map<String, Object>> results = new ArrayList<>();
        for (Map<String, Object> req : requests) {
            Long resourceId = ((Number) req.get("resourceId")).longValue();
            String friendlyName = (String) req.get("friendlyName");
            String description = (String) req.get("description");
            try {
                // If resource already has permission, return existing without overwriting friendlyName
                ManagedResource resource = managedResourceRepository.findById(resourceId).orElse(null);
                if (resource != null && resource.getPermission() != null) {
                    Permission existing = resource.getPermission();
                    results.add(Map.of(
                            "resourceId", resourceId,
                            "permissionId", existing.getId(),
                            "permissionName", existing.getFriendlyName() != null ? existing.getFriendlyName() : "",
                            "skipped", true
                    ));
                    continue;
                }
                ResourceMetadataDto dto = new ResourceMetadataDto();
                dto.setFriendlyName(friendlyName);
                dto.setDescription(description);
                Permission perm = resourceRegistryService.defineResourceAsPermission(resourceId, dto);
                results.add(Map.of(
                        "resourceId", resourceId,
                        "permissionId", perm.getId(),
                        "permissionName", perm.getFriendlyName(),
                        "skipped", false
                ));
            } catch (Exception e) {
                log.error("Batch define failed for resource ID: {}", resourceId, e);
                Map<String, Object> errorResult = new HashMap<>();
                errorResult.put("resourceId", resourceId);
                errorResult.put("error", e.getMessage());
                errorResult.put("skipped", true);
                results.add(errorResult);
            }
        }
        return ResponseEntity.ok(results);
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
            ra.addFlashAttribute("message", msg("msg.resource.status.changed", id));
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", msg("msg.resource.status.change.error", e.getMessage()));
        }
        return "redirect:/admin/workbench/resources";
    }
}