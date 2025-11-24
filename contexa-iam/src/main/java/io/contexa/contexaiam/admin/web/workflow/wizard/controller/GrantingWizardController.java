package io.contexa.contexaiam.admin.web.workflow.wizard.controller;

import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.contexaiam.admin.web.studio.dto.SimulationResultDto;
import io.contexa.contexaiam.admin.web.studio.dto.WizardInitiationDto;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.AssignmentChangeDto;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.InitiateManagementRequestDto;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.WizardContext;
import io.contexa.contexaiam.admin.web.workflow.wizard.service.GrantingWizardService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Map;

@Slf4j
@RequestMapping("/admin/granting-wizard")
@RequiredArgsConstructor
public class GrantingWizardController {

    private final GrantingWizardService grantingWizardService;
    private final UserManagementService userManagementService;
    private final GroupService groupService;
    private final RoleService roleService;

    @PostMapping("/start")
    @ResponseBody
    public ResponseEntity<WizardInitiationDto> startManagementSession(@RequestBody InitiateManagementRequestDto request) {
        return ResponseEntity.ok(grantingWizardService.beginManagementSession(request));
    }

    /**
     * 리소스 워크벤치에서 '빠른 권한 부여'를 선택했을 때 form-data를 처리하는 엔드포인트.
     */
    @PostMapping("/start/from-resource")
    public String startWizardFromResource(@RequestParam Long permissionId, RedirectAttributes ra) {
        log.info("'리소스 워크벤치'로부터 권한 부여 마법사를 시작합니다. Permission ID: {}", permissionId);

        InitiateManagementRequestDto request = new InitiateManagementRequestDto();
        // 빠른 권한 부여는 'Permission' 을 'Role' 에 부여하는 것이므로, subject는 Permission이 됩니다.
        request.setSubjectId(permissionId);
        request.setSubjectType("PERMISSION");

        WizardInitiationDto initiation = grantingWizardService.beginManagementSession(request);

        // 마법사 페이지로 리다이렉트
        return "redirect:" + initiation.wizardUrl();
    }

    @GetMapping("/{contextId}")
    public String getWizardPage(@PathVariable String contextId, Model model, RedirectAttributes ra) {
        try {
            WizardContext context = grantingWizardService.getWizardProgress(contextId);
            WizardContext.Subject subject = context.targetSubject();

            String assignmentType;
            Object allAssignments;

            if ("USER".equalsIgnoreCase(subject.type())) {
                assignmentType = "GROUP";
                allAssignments = groupService.getAllGroups();
            } else if ("GROUP".equalsIgnoreCase(subject.type())) {
                assignmentType = "ROLE";
                allAssignments = roleService.getRoles();
            } else {
                throw new IllegalArgumentException("지원되지 않는 주체 타입입니다: " + subject.type());
            }

            model.addAttribute("contextId", context.contextId());
            model.addAttribute("subjectName", context.sessionTitle().replace("'님의 멤버십 관리", ""));
            model.addAttribute("subjectType", subject.type());
            model.addAttribute("assignmentType", assignmentType);
            model.addAttribute("allAssignments", allAssignments);
            model.addAttribute("selectedAssignmentIds", context.initialAssignmentIds());

            return "admin/granting-wizard";

        } catch (Exception e) {
            log.error("Error loading wizard page for context {}", contextId, e);
            ra.addFlashAttribute("errorMessage", "마법사 페이지 로딩 중 오류 발생: " + e.getMessage());
            return "redirect:/admin/studio";
        }
    }

    @PostMapping("/{contextId}/simulate")
    @ResponseBody
    public ResponseEntity<SimulationResultDto> simulateChanges(
            @PathVariable String contextId,
            @RequestBody AssignmentChangeDto changes) {
        SimulationResultDto result = grantingWizardService.simulateAssignmentChanges(contextId, changes);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/{contextId}/commit")
    public ResponseEntity<Map<String, String>> commitAssignments(
            @PathVariable String contextId,
            @RequestBody AssignmentChangeDto finalAssignments,
            RedirectAttributes ra) {
        grantingWizardService.commitAssignments(contextId, finalAssignments);
        ra.addFlashAttribute("message", "성공적으로 저장되었습니다.");
        return ResponseEntity.ok(Map.of("redirectUrl", "/admin/studio"));
    }
}