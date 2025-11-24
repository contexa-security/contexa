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
// import io.contexa.contexaiam.workflow.wizard.dto.*; // 패키지 존재하지 않음
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

/**
 * [최종 구현] 권한 부여 마법사의 전체 UI 흐름과 각 단계별 API 요청을 처리하는 컨트롤러입니다.
 * 명확한 DTO를 사용하여 안정적인 API 계약을 보장하고, PermissionWizardService에 작업을 위임합니다.
 */
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

    /**
     * Authorization Studio 등 외부에서 권한 부여 워크플로우를 시작하는 진입점입니다.
     * 초기 데이터를 받아 마법사 컨텍스트를 생성하고, 생성된 컨텍스트 ID를 포함한 마법사 첫 페이지로 리다이렉트합니다.
     */
    @PostMapping("/start")
    public String startWizard(@ModelAttribute InitiateGrantRequestDto request, RedirectAttributes ra) {
        String policyName = "신규 권한 할당 정책 - " + System.currentTimeMillis();
        String policyDescription = "마법사를 통해 생성된 신규 권한 할당 정책입니다.";

        WizardContext createdContext = wizardService.beginCreation(request, policyName, policyDescription);

        ra.addFlashAttribute("wizardContext", createdContext);
        ra.addFlashAttribute("fromWorkbench", true);

        return "redirect:/admin/policy-wizard/" + createdContext.contextId();
    }

    /**
     * 마법사 UI 페이지를 렌더링합니다.
     * URL 경로의 contextId를 사용하여 현재 진행 중인 마법사의 상태를 조회하고,
     * 각 단계에 필요한 데이터(전체 사용자/그룹/권한 목록)를 모델에 담아 뷰에 전달합니다.
     */
    @GetMapping("/{contextId}")
    public String getWizardPage(
        @PathVariable String contextId,
        @RequestParam(required = false) String from,
        @RequestParam(required = false) String permName,
        Model model,
        RedirectAttributes ra) {

        WizardContext context;
        // 1. 모델에 Flash Attribute로 전달된 wizardContext가 있는지 확인
        if (model.containsAttribute("wizardContext")) {
            context = (WizardContext) model.asMap().get("wizardContext");
            log.info("Retrieved WizardContext from Flash Attributes for ID: {}", contextId);
        } else {
            // 2. 없다면(예: 페이지 새로고침) DB에서 조회
            log.info("No Flash Attribute found. Retrieving WizardContext from DB for ID: {}", contextId);
            context = wizardService.getWizardProgress(contextId);
        }

        if (context == null) {
            throw new IllegalStateException("유효하지 않거나 만료된 마법사 세션입니다.");
        }

        // 워크벤치에서 넘어온 경우, 권한 정보 처리
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
//        model.addAttribute("allUsers", userManagementService.getUsers());
//        model.addAttribute("allGroups", groupService.getAllGroups());
        model.addAttribute("allRoles", roleService.getRoles());
        model.addAttribute("allPermissions", permissionCatalogService.getAvailablePermissions());
        model.addAttribute("activePage", "policy-wizard");
        return "admin/policy-wizard";
    }

    /**
     * API: Step 1(주체 선택)의 데이터를 받아 마법사 컨텍스트를 업데이트합니다.
     */
    @PostMapping("/{contextId}/subjects")
    public ResponseEntity<WizardContext> saveSubjects(@PathVariable String contextId, @RequestBody SaveSubjectsRequest request) {
        log.debug("API: Saving subjects for contextId: {}", contextId);
        WizardContext updatedContext = wizardService.updateSubjects(contextId, request);
        return ResponseEntity.ok(updatedContext);
    }

    /**
     * API: Step 2(권한 선택)의 데이터를 받아 마법사 컨텍스트를 업데이트합니다.
     */
    @PostMapping("/{contextId}/permissions")
    public ResponseEntity<WizardContext> savePermissions(@PathVariable String contextId, @RequestBody SavePermissionsRequest request) {
        log.debug("API: Saving permissions for contextId: {}", contextId);
        WizardContext updatedContext = wizardService.updatePermissions(contextId, request);
        return ResponseEntity.ok(updatedContext);
    }

    /**
     * API: Step 3(검토 및 생성)에서 최종 정책을 생성하고 저장합니다.
     */
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