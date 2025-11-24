package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.contexaiam.admin.web.studio.controller.AuthorizationStudioController;
import io.contexa.contexaiam.admin.web.studio.service.StudioActionService;
import io.contexa.contexaiam.admin.web.studio.service.StudioExplorerService;
import io.contexa.contexaiam.admin.web.studio.service.StudioVisualizerService;
import io.contexa.contexaiam.admin.web.studio.service.impl.StudioActionServiceImpl;
import io.contexa.contexaiam.admin.web.studio.service.impl.StudioExplorerServiceImpl;
import io.contexa.contexaiam.admin.web.studio.service.impl.StudioVisualizerServiceImpl;
import io.contexa.contexaiam.admin.web.workflow.wizard.service.PermissionWizardService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyBuilderService;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.UserRepository;
import org.modelmapper.ModelMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class IamAdminStudioAutoConfiguration {

    // Controllers (1개)
    @Bean
    @ConditionalOnMissingBean
    public AuthorizationStudioController authorizationStudioController(
            StudioExplorerService explorerService,
            StudioVisualizerService visualizerService,
            StudioActionService actionService) {
        return new AuthorizationStudioController(explorerService, visualizerService, actionService);
    }

    // Services (3개)
    @Bean
    @ConditionalOnMissingBean
    public StudioExplorerService studioExplorerService(
            UserRepository userRepository,
            GroupRepository groupRepository) {
        return new StudioExplorerServiceImpl(userRepository, groupRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public StudioVisualizerService studioVisualizerService(
            UserRepository userRepository,
            GroupRepository groupRepository,
            PermissionRepository permissionRepository,
            UserManagementService userManagementService,
            GroupService groupService,
            ModelMapper modelMapper) {
        return new StudioVisualizerServiceImpl(
                userRepository, groupRepository, permissionRepository,
                userManagementService, groupService, modelMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public StudioActionService studioActionService(
            PolicyBuilderService policyBuilderService,
            PermissionWizardService permissionWizardService,
            ModelMapper modelMapper) {
        return new StudioActionServiceImpl(policyBuilderService, permissionWizardService, modelMapper);
    }
}
