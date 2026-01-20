package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexaiam.admin.support.context.service.UserContextService;
import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.admin.web.workflow.orchestrator.service.WorkflowOrchestrator;
import io.contexa.contexaiam.admin.web.workflow.orchestrator.service.WorkflowOrchestratorImpl;
import io.contexa.contexaiam.admin.web.workflow.translator.BusinessPolicyTranslator;
import io.contexa.contexaiam.admin.web.workflow.translator.BusinessPolicyTranslatorImpl;
import io.contexa.contexaiam.admin.web.workflow.wizard.controller.GrantingWizardController;
import io.contexa.contexaiam.admin.web.workflow.wizard.controller.PolicyWizardController;
import io.contexa.contexaiam.admin.web.workflow.wizard.service.GrantingWizardService;
import io.contexa.contexaiam.admin.web.workflow.wizard.service.GrantingWizardServiceImpl;
import io.contexa.contexaiam.admin.web.workflow.wizard.service.PermissionWizardService;
import io.contexa.contexaiam.admin.web.workflow.wizard.service.PermissionWizardServiceImpl;
import io.contexa.contexaiam.admin.web.studio.service.StudioVisualizerService;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import org.modelmapper.ModelMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class IamAdminWorkflowAutoConfiguration {

    
    @Bean
    @ConditionalOnMissingBean
    public PolicyWizardController policyWizardController(
            PermissionWizardService wizardService,
            UserManagementService userManagementService,
            GroupService groupService,
            PermissionCatalogService permissionCatalogService,
            PermissionService permissionService,
            RoleService roleService,
            ModelMapper modelMapper) {
        return new PolicyWizardController(
                wizardService, userManagementService, groupService,
                permissionCatalogService, permissionService, roleService, modelMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public GrantingWizardController grantingWizardController(
            GrantingWizardService grantingWizardService,
            UserManagementService userManagementService,
            GroupService groupService,
            RoleService roleService) {
        return new GrantingWizardController(
                grantingWizardService, userManagementService, groupService, roleService);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public PermissionWizardService permissionWizardService(
            UserContextService userContextService,
            RoleService roleService) {
        return new PermissionWizardServiceImpl(userContextService, roleService);
    }

    @Bean
    @ConditionalOnMissingBean
    public GrantingWizardService grantingWizardService(
            UserContextService userContextService,
            UserManagementService userManagementService,
            GroupService groupService,
            RoleRepository roleRepository,
            UserRepository userRepository,
            GroupRepository groupRepository,
            StudioVisualizerService visualizerService) {
        return new GrantingWizardServiceImpl(
                userContextService, userManagementService, groupService,
                roleRepository, userRepository, groupRepository, visualizerService);
    }

    @Bean
    @ConditionalOnMissingBean
    public WorkflowOrchestrator workflowOrchestrator(PermissionWizardService permissionWizardService) {
        return new WorkflowOrchestratorImpl(permissionWizardService);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public BusinessPolicyTranslator businessPolicyTranslator(
            PermissionRepository permissionRepository) {
        return new BusinessPolicyTranslatorImpl(permissionRepository);
    }
}
