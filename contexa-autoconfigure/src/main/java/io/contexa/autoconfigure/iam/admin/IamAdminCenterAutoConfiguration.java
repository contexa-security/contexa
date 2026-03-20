package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.center.PolicyCenterController;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.admin.web.studio.service.StudioActionService;
import io.contexa.contexaiam.admin.web.studio.service.StudioExplorerService;
import io.contexa.contexaiam.admin.web.studio.service.StudioVisualizerService;
import io.contexa.contexaiam.resource.service.ConditionCompatibilityService;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class IamAdminCenterAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public PolicyCenterController policyCenterController(
            ResourceRegistryService resourceRegistryService,
            PolicyService policyService,
            RoleService roleService,
            PermissionService permissionService,
            PermissionCatalogService permissionCatalogService,
            ConditionCompatibilityService conditionCompatibilityService,
            StudioExplorerService explorerService,
            StudioVisualizerService visualizerService,
            StudioActionService actionService) {
        return new PolicyCenterController(
                resourceRegistryService, policyService, roleService,
                permissionService, permissionCatalogService,
                conditionCompatibilityService, explorerService,
                visualizerService, actionService);
    }
}
