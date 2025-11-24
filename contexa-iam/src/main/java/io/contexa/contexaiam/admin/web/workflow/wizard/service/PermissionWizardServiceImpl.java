package io.contexa.contexaiam.admin.web.workflow.wizard.service;

import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.support.context.service.UserContextService;
import io.contexa.contexaiam.domain.dto.UserDto;
import io.contexa.contexaiam.security.core.CustomUserDetails;
import io.contexa.contexaiam.admin.web.studio.dto.InitiateGrantRequestDto;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.SavePermissionsRequest;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.SaveSubjectsRequest;
import io.contexa.contexaiam.admin.web.workflow.wizard.dto.WizardContext;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.Users;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;

import java.util.*;
import java.util.stream.Collectors;

/**
 * [최종 수정 및 완성]
 * RBAC 중심의 아키텍처에 맞춰, 권한 부여 마법사의 역할을 '권한을 역할에 할당'하는 것으로 명확히 하고
 * 관련 모든 메서드를 최종 구현합니다.
 */
@Slf4j
@RequiredArgsConstructor
public class PermissionWizardServiceImpl implements PermissionWizardService {

    private final UserContextService userContextService;
    private final RoleService roleService;

    @Override
    @Transactional
    public WizardContext beginCreation(InitiateGrantRequestDto request, String policyName, String policyDescription) {
        String contextId = UUID.randomUUID().toString();
        log.info("Beginning new permission grant wizard. Context ID: {}", contextId);

        WizardContext initialContext = WizardContext.builder()
                .contextId(contextId)
                .sessionTitle(policyName)
                .sessionDescription(policyDescription)
                .subjects(new HashSet<>()) // 초기 주체(역할)는 비어있음
                .permissionIds(request.getPermissionIds()) // 워크벤치에서 전달된 권한 ID 설정
                .build();

        userContextService.saveWizardProgress(contextId, getCurrentUserId(), initialContext);
        return initialContext;
    }

    @Override
    public WizardContext getWizardProgress(String contextId) {
        return userContextService.getWizardProgress(contextId);
    }

    /**
     * [최종 구현] 마법사의 '역할 선택' 단계를 저장합니다.
     * 이제 주체(Subject)는 역할(Role)을 의미합니다.
     */
    @Override
    @Transactional
    public WizardContext updateSubjects(String contextId, SaveSubjectsRequest request) {
        WizardContext currentContext = userContextService.getWizardProgress(contextId);
        log.info("Updating selected roles for wizard context: {}", contextId);

        // request의 userIds가 실제로는 roleId를 담고 있다고 가정하고 로직을 수정합니다.
        // DTO 이름을 명확하게 바꾸는 것이 장기적으로 좋습니다. (예: SaveRolesRequest)
        Set<WizardContext.Subject> selectedRoles = request.userIds().stream()
                .map(roleId -> new WizardContext.Subject(roleId, "ROLE"))
                .collect(Collectors.toSet());

        WizardContext updatedContext = WizardContext.builder()
                .contextId(currentContext.contextId())
                .sessionTitle(currentContext.sessionTitle())
                .sessionDescription(currentContext.sessionDescription())
                .subjects(selectedRoles) // 새로운 역할 정보로 교체
                .permissionIds(currentContext.permissionIds())
                .build();

        userContextService.saveWizardProgress(contextId, getCurrentUserId(), updatedContext);
        return updatedContext;
    }

    @Override
    @Transactional
    public WizardContext updatePermissions(String contextId, SavePermissionsRequest request) {
        WizardContext currentContext = userContextService.getWizardProgress(contextId);
        log.info("Updating permissions for wizard context: {}", contextId);

        WizardContext updatedContext = WizardContext.builder()
                .contextId(currentContext.contextId())
                .sessionTitle(currentContext.sessionTitle())
                .sessionDescription(currentContext.sessionDescription())
                .subjects(currentContext.subjects())
                .permissionIds(request.permissionIds()) // 새로운 권한 정보로 교체
                .build();

        userContextService.saveWizardProgress(contextId, getCurrentUserId(), updatedContext);
        return updatedContext;
    }

    @Override
    @Transactional
    public void updatePolicyDetails(String contextId, String policyName, String policyDescription) {
        WizardContext currentContext = userContextService.getWizardProgress(contextId);
        log.info("Updating policy details for wizard context: {}", contextId);

        WizardContext updatedContext = WizardContext.builder()
                .contextId(currentContext.contextId())
                .sessionTitle(policyName)
                .sessionDescription(policyDescription)
                .subjects(currentContext.subjects())
                .permissionIds(currentContext.permissionIds())
                .build();

        userContextService.saveWizardProgress(contextId, getCurrentUserId(), updatedContext);
    }

    /**
     * [최종 구현] 마법사의 최종 '적용' 단계입니다.
     * 선택된 역할(들)에 선택된 권한을 할당하는 작업을 RoleService에 위임합니다.
     */
    @Override
    @Transactional
    public void commitPolicy(String contextId, List<Long> selectedRoleIds, Set<Long> permissionIds) {
        log.info("Committing permission-to-role assignment for wizard context: {}", contextId);

        if (CollectionUtils.isEmpty(selectedRoleIds) || CollectionUtils.isEmpty(permissionIds)) {
            throw new IllegalStateException("역할과 권한이 반드시 선택되어야 합니다.");
        }

        // 마법사는 현재 단일 권한 할당을 전제로 동작
        Long permissionIdToAdd = permissionIds.iterator().next();

        for (Long roleId : selectedRoleIds) {
            Role role = roleService.getRole(roleId);

            List<Long> existingPermIds = role.getRolePermissions().stream()
                    .map(rp -> rp.getPermission().getId())
                    .toList();

            if (!existingPermIds.contains(permissionIdToAdd)) {
                List<Long> newPermissionIds = new ArrayList<>(existingPermIds);
                newPermissionIds.add(permissionIdToAdd);
                // 역할 업데이트 -> 이 메서드 내부에서 정책 동기화 이벤트가 발생해야 함
                roleService.updateRole(role, newPermissionIds);
            }
        }

        userContextService.clearWizardProgress(contextId);
    }

    private Long getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
            log.warn("No authenticated user found.");
            return null;
        }

        Object principal = authentication.getPrincipal();

        if (principal instanceof CustomUserDetails userDetails) {
            return userDetails.getUsers().getId();
        } else if (principal instanceof Users user) {
            return user.getId();
        } else if (principal instanceof UserDto userDto) {
            return userDto.getId(); // [핵심] UserDto 타입 처리
        }

        log.warn("Principal is not an instance of a recognized user type. Principal type: {}. Returning null.", principal.getClass().getName());
        return null;
    }
}