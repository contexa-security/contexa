package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.center.PolicyCenterController;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@AutoConfigureAfter({
        IamAdminAuthAutoConfiguration.class,
        IamAdminStudioAutoConfiguration.class
})
public class IamAdminCenterAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public PolicyCenterController policyCenterController(
            ResourceRegistryService resourceRegistryService,
            PolicyService policyService,
            RoleService roleService) {
        return new PolicyCenterController(
                resourceRegistryService, policyService, roleService);
    }
}
