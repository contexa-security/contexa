package io.contexa.contexaiam.admin.web.workflow.wizard.controller;

import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.CommitWizardRequest;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.SavePermissionsRequest;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.SaveSubjectsRequest;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.WizardContext;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexaiam.admin.web.studio.dto.InitiateGrantRequestDto;

import io.contexa.contexaiam.admin.web.workflow.wizard.service.PermissionWizardService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.util.CollectionUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.stereotype.Controller;

@Slf4j
@Controller
@RequestMapping("/admin/policy-wizard")
@RequiredArgsConstructor
public class PolicyWizardController {

    private final PermissionWizardService wizardService;
    private final UserManagementService userManagementService;
    private final GroupService groupService;
    private final PermissionCatalogService permissionCatalogService;
    private final PermissionService permissionService;
    private final RoleService roleService;
    private final ModelMapper modelMapper;

    @PostMapping("/start")
    public String startWizard(@ModelAttribute InitiateGrantRequestDto request, RedirectAttributes ra) {
        String policyName = "New Permission Assignment Policy - " + System.currentTimeMillis();
        String policyDescription = "A new permission assignment policy created through the wizard.";

        WizardContext createdContext = wizardService.beginCreation(request, policyName, policyDescription);

        ra.addFlashAttribute("wizardContext", createdContext);
        ra.addFlashAttribute("fromWorkbench", true);

        return "redirect:/admin/policy-wizard/" + createdContext.contextId();
    }

    @GetMapping("/{contextId}")
    public String getWizardPage(
        @PathVariable String contextId,
        @RequestParam(required = false) String from,
        @RequestParam(required = false) String permName,
        Model model,
        RedirectAttributes ra) {

        WizardContext context;
        
        if (model.containsAttribute("wizardContext")) {
            context = (WizardContext) model.asMap().get("wizardContext");
                    } else {
            
                        context = wizardService.getWizardProgress(contextId);
        }

        if (context == null) {
            throw new IllegalStateException("Invalid or expired wizard session.");
        }

        if (model.containsAttribute("fromWorkbench") && !CollectionUtils.isEmpty(context.permissionIds())) {
            Long preselectedPermissionId = context.permissionIds().iterator().next();
            permissionService.getPermission(preselectedPermissionId)
                    .ifPresent(permission -> {
                        PermissionDto permissionDto = modelMapper.map(permission, PermissionDto.class);
                        model.addAttribute("preselectedPermission", permissionDto);
                        String friendlyName = permission.getFriendlyName() != null ? permission.getFriendlyName() : permission.getName();
                        model.addAttribute("message", "Permission '" + friendlyName + "' has been created. Now select the subjects (roles/groups) to grant this permission to.");
                    });
        }

        model.addAttribute("wizardContext", context);

        model.addAttribute("allRoles", roleService.getRoles());
        model.addAttribute("allPermissions", permissionCatalogService.getAvailablePermissions());
        model.addAttribute("activePage", "policy-wizard");
        return "admin/policy-wizard";
    }

    @GetMapping("/{contextId}/available-permissions")
    @ResponseBody
    public ResponseEntity<List<PermissionDto>> getAvailablePermissions(
            @PathVariable String contextId,
            @RequestParam List<Long> roleIds) {

        List<PermissionDto> allPermissions = permissionCatalogService.getAvailablePermissions();

        Set<Long> existingPermissionIds = new HashSet<>();
        for (Long roleId : roleIds) {
            roleService.getRole(roleId).getRolePermissions().stream()
                    .map(rp -> rp.getPermission().getId())
                    .forEach(existingPermissionIds::add);
        }

        List<PermissionDto> filtered = allPermissions.stream()
                .filter(p -> !existingPermissionIds.contains(p.getId()))
                .toList();

        return ResponseEntity.ok(filtered);
    }

    @PostMapping("/{contextId}/subjects")
    @ResponseBody
    public ResponseEntity<WizardContext> saveSubjects(@PathVariable String contextId, @RequestBody SaveSubjectsRequest request) {
                WizardContext updatedContext = wizardService.updateSubjects(contextId, request);
        return ResponseEntity.ok(updatedContext);
    }

    @PostMapping("/{contextId}/permissions")
    @ResponseBody
    public ResponseEntity<WizardContext> savePermissions(@PathVariable String contextId, @RequestBody SavePermissionsRequest request) {
                WizardContext updatedContext = wizardService.updatePermissions(contextId, request);
        return ResponseEntity.ok(updatedContext);
    }

    @PostMapping("/{contextId}/commit")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> commitPolicy(
            @PathVariable String contextId,
            @RequestBody CommitWizardRequest request) {

        wizardService.updatePolicyDetails(contextId, request.getPolicyName(), request.getPolicyDescription());
        wizardService.commitPolicy(contextId, request.getSelectedRoleIds(), request.getPermissionIds());

        Map<String, Object> response = Map.of("success", true, "message", "Permissions have been successfully assigned to the role.");
        return ResponseEntity.ok(response);
    }
}