package io.contexa.contexaiam.admin.web.metadata.controller;

import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceBatchDefineRequest;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceBatchDefineResult;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceDefineResponse;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceManagementForm;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceMetadataForm;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceSearchForm;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceStatusResponse;
import io.contexa.contexaiam.admin.web.metadata.dto.ResourceAdminDtos.ResourceWorkbenchPageModel;
import io.contexa.contexaiam.admin.web.metadata.service.ResourceAdminService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

@Controller
@RequestMapping("/admin/workbench/resources")
@RequiredArgsConstructor
@Slf4j
public class ResourceAdminController {

    private final ResourceAdminService resourceAdminService;

    @GetMapping
    public String resourceWorkbenchPage(
            @ModelAttribute("criteria") ResourceSearchForm criteria,
            @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable,
            Model model) {

        model.addAttribute("activePage", "policy-center");
        ResourceWorkbenchPageModel pageModel = resourceAdminService.getWorkbenchPage(criteria, pageable);

        model.addAttribute("resourcePage", pageModel.resourcePage());
        model.addAttribute("serviceOwners", pageModel.serviceOwners());
        model.addAttribute("criteria", pageModel.criteria());
        return "admin/resource-workbench";
    }

    @PostMapping("/refresh")
    public String refreshResources(RedirectAttributes ra) {
        try {
            resourceAdminService.refreshResources();
            ra.addFlashAttribute("message", resourceAdminService.message("msg.resource.refreshed"));
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", resourceAdminService.message("msg.resource.refresh.error", e.getMessage()));
        }
        return "redirect:/admin/workbench/resources";
    }

    @PostMapping("/{id}/define")
    @ResponseBody
    public ResponseEntity<ResourceDefineResponse> defineResourceAsPermissionApi(
            @PathVariable Long id,
            @ModelAttribute ResourceMetadataForm metadataForm) {
        try {
            return ResponseEntity.ok(resourceAdminService.defineResourceAsPermission(id, metadataForm));
        } catch (Exception e) {
            log.error("Permission definition API failed for resource ID: {}", id, e);
            return ResponseEntity.badRequest().body(ResourceDefineResponse.error(e.getMessage()));
        }
    }

    @PostMapping("/define-batch")
    @ResponseBody
    public ResponseEntity<List<ResourceBatchDefineResult>> defineResourcesBatch(
            @RequestBody(required = false) List<ResourceBatchDefineRequest> requests) {
        if (requests == null) {
            return ResponseEntity.badRequest()
                    .body(List.of(ResourceBatchDefineResult.error(null, "request body is required")));
        }
        return ResponseEntity.ok(resourceAdminService.defineResourcesBatch(requests));
    }

    @PostMapping("/{id}/restore")
    @ResponseBody
    public ResponseEntity<ResourceStatusResponse> restoreResource(@PathVariable Long id) {
        try {
            return ResponseEntity.ok(resourceAdminService.restoreResource(id));
        } catch (Exception e) {
            log.error("Resource restore failed for ID: {}", id, e);
            return ResponseEntity.badRequest().body(ResourceStatusResponse.error(e.getMessage()));
        }
    }

    @PostMapping("/{id}/exclude")
    @ResponseBody
    public ResponseEntity<ResourceStatusResponse> excludeResource(@PathVariable Long id) {
        try {
            return ResponseEntity.ok(resourceAdminService.excludeResource(id));
        } catch (Exception e) {
            log.error("Resource exclude failed for ID: {}", id, e);
            return ResponseEntity.badRequest().body(ResourceStatusResponse.error(e.getMessage()));
        }
    }

    @PostMapping("/{id}/manage")
    public String updateManagementStatus(
            @PathVariable Long id,
            @ModelAttribute ResourceManagementForm managementForm,
            RedirectAttributes ra) {
        try {
            resourceAdminService.updateManagementStatus(id, managementForm);
            ra.addFlashAttribute("message", resourceAdminService.message("msg.resource.status.changed", id));
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", resourceAdminService.message("msg.resource.status.change.error", e.getMessage()));
        }
        return "redirect:/admin/workbench/resources";
    }
}
