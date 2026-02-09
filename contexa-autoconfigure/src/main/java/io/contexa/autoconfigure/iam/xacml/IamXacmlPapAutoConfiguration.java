package io.contexa.autoconfigure.iam.xacml;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.common.event.service.IntegrationEventBus;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.PolicyTemplateRepository;
import io.contexa.contexaiam.resource.service.ConditionCompatibilityService;
import io.contexa.contexaiam.security.xacml.pap.controller.PolicyApiController;
import io.contexa.contexaiam.security.xacml.pap.controller.PolicyBuilderController;
import io.contexa.contexaiam.security.xacml.pap.controller.PolicyController;
import io.contexa.contexaiam.security.xacml.pap.service.*;
import io.contexa.contexaiam.security.xacml.pdp.translator.PolicyTranslator;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import org.modelmapper.ModelMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Lazy;


@AutoConfiguration
public class IamXacmlPapAutoConfiguration {

    
    @Bean
    @ConditionalOnMissingBean
    public PolicyEnrichmentService policyEnrichmentService(PolicyTranslator policyTranslator) {
        return new PolicyEnrichmentService(policyTranslator);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicySynchronizationService policySynchronizationService(
            PolicyRepository policyRepository,
            RoleRepository roleRepository,
            PolicyService policyService) {
        return new PolicySynchronizationService(policyRepository, roleRepository, policyService);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyService defaultPolicyService(
            PolicyRepository policyRepository,
            PolicyRetrievalPoint policyRetrievalPoint,
            CustomDynamicAuthorizationManager authorizationManager,
            PolicyEnrichmentService policyEnrichmentService,
            IntegrationEventBus eventBus,
            PermissionRepository permissionRepository) {
        return new DefaultPolicyService(
                policyRepository, policyRetrievalPoint, authorizationManager,
                policyEnrichmentService, eventBus, permissionRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyBuilderService policyBuilderService(
            PolicyRepository policyRepository,
            UserRepository userRepository,
            PermissionRepository permissionRepository,
            PolicyTemplateRepository policyTemplateRepository,
            PolicyService policyService,
            ModelMapper modelMapper,
            ObjectMapper objectMapper) {
        return new PolicyBuilderServiceImpl(
                policyRepository, userRepository, permissionRepository,
                policyTemplateRepository, policyService, modelMapper, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public BusinessPolicyService businessPolicyService(
            PolicyRepository policyRepository,
            @Lazy RoleService roleService,
            RoleRepository roleRepository,
            PermissionRepository permissionRepository,
            ConditionTemplateRepository conditionTemplateRepository,
            PolicyEnrichmentService policyEnrichmentService,
            CustomDynamicAuthorizationManager authorizationManager) {
        return new BusinessPolicyServiceImpl(
                policyRepository, roleService, roleRepository, permissionRepository,
                conditionTemplateRepository, policyEnrichmentService, authorizationManager);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyController policyController(
            PolicyService policyService,
            ModelMapper modelMapper) {
        return new PolicyController(policyService, modelMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyApiController policyApiController(
            BusinessPolicyService businessPolicyService,
            ModelMapper modelMapper) {
        return new PolicyApiController(businessPolicyService, modelMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyBuilderController policyBuilderController(
            RoleService roleService,
            PermissionCatalogService permissionCatalogService,
            ConditionTemplateRepository conditionTemplateRepository,
            ManagedResourceRepository managedResourceRepository,
            ObjectMapper objectMapper,
            PermissionService permissionService,
            ConditionCompatibilityService conditionCompatibilityService) {
        return new PolicyBuilderController(
                roleService, permissionCatalogService, conditionTemplateRepository, managedResourceRepository,
                objectMapper, permissionService, conditionCompatibilityService);
    }
}
