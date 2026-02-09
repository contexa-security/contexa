package io.contexa.contexaiam.admin.web.workflow.wizard.service;

import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.support.context.service.UserContextService;
import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
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

@Slf4j
@RequiredArgsConstructor
public class PermissionWizardServiceImpl implements PermissionWizardService {

    private final UserContextService userContextService;
    private final RoleService roleService;

    @Override
    @Transactional
    public WizardContext beginCreation(InitiateGrantRequestDto request, String policyName, String policyDescription) {
        String contextId = UUID.randomUUID().toString();
        
        WizardContext initialContext = WizardContext.builder()
                .contextId(contextId)
                .sessionTitle(policyName)
                .sessionDescription(policyDescription)
                .subjects(new HashSet<>()) 
                .permissionIds(request.getPermissionIds()) 
                .build();

        userContextService.saveWizardProgress(contextId, getCurrentUserId(), initialContext);
        return initialContext;
    }

    @Override
    public WizardContext getWizardProgress(String contextId) {
        return userContextService.getWizardProgress(contextId);
    }

    @Override
    @Transactional
    public WizardContext updateSubjects(String contextId, SaveSubjectsRequest request) {
        WizardContext currentContext = userContextService.getWizardProgress(contextId);

        Set<WizardContext.Subject> selectedRoles = request.userIds().stream()
                .map(roleId -> new WizardContext.Subject(roleId, "ROLE"))
                .collect(Collectors.toSet());

        WizardContext updatedContext = WizardContext.builder()
                .contextId(currentContext.contextId())
                .sessionTitle(currentContext.sessionTitle())
                .sessionDescription(currentContext.sessionDescription())
                .subjects(selectedRoles) 
                .permissionIds(currentContext.permissionIds())
                .build();

        userContextService.saveWizardProgress(contextId, getCurrentUserId(), updatedContext);
        return updatedContext;
    }

    @Override
    @Transactional
    public WizardContext updatePermissions(String contextId, SavePermissionsRequest request) {
        WizardContext currentContext = userContextService.getWizardProgress(contextId);
        
        WizardContext updatedContext = WizardContext.builder()
                .contextId(currentContext.contextId())
                .sessionTitle(currentContext.sessionTitle())
                .sessionDescription(currentContext.sessionDescription())
                .subjects(currentContext.subjects())
                .permissionIds(request.permissionIds()) 
                .build();

        userContextService.saveWizardProgress(contextId, getCurrentUserId(), updatedContext);
        return updatedContext;
    }

    @Override
    @Transactional
    public void updatePolicyDetails(String contextId, String policyName, String policyDescription) {
        WizardContext currentContext = userContextService.getWizardProgress(contextId);
        
        WizardContext updatedContext = WizardContext.builder()
                .contextId(currentContext.contextId())
                .sessionTitle(policyName)
                .sessionDescription(policyDescription)
                .subjects(currentContext.subjects())
                .permissionIds(currentContext.permissionIds())
                .build();

        userContextService.saveWizardProgress(contextId, getCurrentUserId(), updatedContext);
    }

    @Override
    @Transactional
    public void commitPolicy(String contextId, List<Long> selectedRoleIds, Set<Long> permissionIds) {
        
        if (CollectionUtils.isEmpty(selectedRoleIds) || CollectionUtils.isEmpty(permissionIds)) {
            throw new IllegalStateException("역할과 권한이 반드시 선택되어야 합니다.");
        }
        Long permissionIdToAdd = permissionIds.iterator().next();
        for (Long roleId : selectedRoleIds) {
            Role role = roleService.getRole(roleId);

            List<Long> existingPermIds = role.getRolePermissions().stream()
                    .map(rp -> rp.getPermission().getId())
                    .toList();

            if (!existingPermIds.contains(permissionIdToAdd)) {
                List<Long> newPermissionIds = new ArrayList<>(existingPermIds);
                newPermissionIds.add(permissionIdToAdd);
                
                roleService.updateRole(role, newPermissionIds);
            }
        }
        userContextService.clearWizardProgress(contextId);
    }

    private String getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
            log.warn("No authenticated user found.");
            return null;
        }
        return authentication.getName();
    }
}