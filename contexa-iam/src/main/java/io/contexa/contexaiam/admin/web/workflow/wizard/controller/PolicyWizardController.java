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

import java.util.Map;


@Slf4j
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
        String policyName = "신규 권한 할당 정책 - " + System.currentTimeMillis();
        String policyDescription = "마법사를 통해 생성된 신규 권한 할당 정책입니다.";

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
            log.info("Retrieved WizardContext from Flash Attributes for ID: {}", contextId);
        } else {
            
            log.info("No Flash Attribute found. Retrieving WizardContext from DB for ID: {}", contextId);
            context = wizardService.getWizardProgress(contextId);
        }

        if (context == null) {
            throw new IllegalStateException("유효하지 않거나 만료된 마법사 세션입니다.");
        }

        
        if (model.containsAttribute("fromWorkbench") && !CollectionUtils.isEmpty(context.permissionIds())) {
            Long preselectedPermissionId = context.permissionIds().iterator().next();
            permissionService.getPermission(preselectedPermissionId)
                    .ifPresent(permission -> {
                        PermissionDto permissionDto = modelMapper.map(permission, PermissionDto.class);
                        model.addAttribute("preselectedPermission", permissionDto);
                        String friendlyName = permission.getFriendlyName() != null ? permission.getFriendlyName() : permission.getName();
                        model.addAttribute("message", "권한 '" + friendlyName + "'이(가) 생성되었습니다. 이제 이 권한을 부여할 주체(역할/그룹)를 선택하세요.");
                    });
        }

        model.addAttribute("wizardContext", context);


        model.addAttribute("allRoles", roleService.getRoles());
        model.addAttribute("allPermissions", permissionCatalogService.getAvailablePermissions());
        model.addAttribute("activePage", "policy-wizard");
        return "admin/policy-wizard";
    }

    
    @PostMapping("/{contextId}/subjects")
    public ResponseEntity<WizardContext> saveSubjects(@PathVariable String contextId, @RequestBody SaveSubjectsRequest request) {
        log.debug("API: Saving subjects for contextId: {}", contextId);
        WizardContext updatedContext = wizardService.updateSubjects(contextId, request);
        return ResponseEntity.ok(updatedContext);
    }

    
    @PostMapping("/{contextId}/permissions")
    public ResponseEntity<WizardContext> savePermissions(@PathVariable String contextId, @RequestBody SavePermissionsRequest request) {
        log.debug("API: Saving permissions for contextId: {}", contextId);
        WizardContext updatedContext = wizardService.updatePermissions(contextId, request);
        return ResponseEntity.ok(updatedContext);
    }

    
    @PostMapping("/{contextId}/commit")
    public ResponseEntity<Map<String, Object>> commitPolicy(
            @PathVariable String contextId,
            @RequestBody CommitWizardRequest request) {

        wizardService.updatePolicyDetails(contextId, request.getPolicyName(), request.getPolicyDescription());
        wizardService.commitPolicy(contextId, request.getSelectedRoleIds(), request.getPermissionIds());

        Map<String, Object> response = Map.of("success", true, "message", "권한이 역할에 성공적으로 할당되었습니다.");
        return ResponseEntity.ok(response);
    }
}