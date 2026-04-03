package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.center.PolicyCenterController;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pap.service.BusinessPolicyService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyEnrichmentService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyMatrixService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyVersionService;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@AutoConfigureAfter({
        IamAdminAuthAutoConfiguration.class
})
public class IamAdminCenterAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public PolicyCenterController policyCenterController(
            ResourceRegistryService resourceRegistryService,
            PolicyService policyService,
            PolicyRepository policyRepository,
            RoleService roleService,
            PermissionCatalogService permissionCatalogService,
            BusinessPolicyService businessPolicyService,
            ConditionTemplateRepository conditionTemplateRepository,
            ManagedResourceRepository managedResourceRepository,
            io.contexa.contexaiam.repository.SecuritySpelRepository securitySpelRepository,
            MessageSource messageSource,
            PolicyValidationService policyValidationService,
            PermissionRepository permissionRepository,
            PolicyVersionService policyVersionService,
            PolicyMatrixService policyMatrixService,
            PolicyCombiningProperties policyCombiningProperties,
            PolicyEnrichmentService policyEnrichmentService,
            CustomDynamicAuthorizationManager authorizationManager,
            CentralAuditFacade centralAuditFacade) {
        return new PolicyCenterController(
                resourceRegistryService, policyService, policyRepository, roleService,
                permissionCatalogService, businessPolicyService, conditionTemplateRepository,
                managedResourceRepository, securitySpelRepository, messageSource,
                policyValidationService, permissionRepository, policyEnrichmentService,
                policyVersionService, policyMatrixService, policyCombiningProperties,
                authorizationManager, centralAuditFacade);
    }
}
