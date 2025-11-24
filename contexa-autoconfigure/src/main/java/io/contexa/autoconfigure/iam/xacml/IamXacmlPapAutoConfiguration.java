package io.contexa.autoconfigure.iam.xacml;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.contexaiam.admin.web.metadata.service.BusinessMetadataService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.common.event.service.IntegrationEventBus;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.PolicyTemplateRepository;
import io.contexa.contexaiam.resource.service.ConditionCompatibilityService;
import io.contexa.contexaiam.security.xacml.pap.controller.BusinessPolicyController;
import io.contexa.contexaiam.security.xacml.pap.controller.PolicyBuilderController;
import io.contexa.contexaiam.security.xacml.pap.controller.PolicyController;
import io.contexa.contexaiam.security.xacml.pap.service.BusinessPolicyService;
import io.contexa.contexaiam.security.xacml.pap.service.BusinessPolicyServiceImpl;
import io.contexa.contexaiam.security.xacml.pap.service.DefaultPolicyService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyBuilderService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyBuilderServiceImpl;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyEnrichmentService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyOptimizationService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyOptimizationServiceImpl;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicySynchronizationService;
import io.contexa.contexaiam.security.xacml.pdp.translator.PolicyTranslator;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import org.modelmapper.ModelMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Lazy;

/**
 * XACML PAP (Policy Administration Point) AutoConfiguration
 */
@AutoConfiguration
public class IamXacmlPapAutoConfiguration {

    // Services (6개)
    @Bean
    @ConditionalOnMissingBean
    public PolicyEnrichmentService policyEnrichmentService(PolicyTranslator policyTranslator) {
        return new PolicyEnrichmentService(policyTranslator);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyOptimizationService policyOptimizationService(
            PolicyRepository policyRepository,
            ModelMapper modelMapper) {
        return new PolicyOptimizationServiceImpl(policyRepository, modelMapper);
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
            ModelMapper modelMapper,
            IntegrationEventBus eventBus,
            PermissionRepository permissionRepository) {
        return new DefaultPolicyService(
                policyRepository, policyRetrievalPoint, authorizationManager,
                policyEnrichmentService, modelMapper, eventBus, permissionRepository);
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

    // Controllers (3개)
    @Bean
    @ConditionalOnMissingBean
    public BusinessPolicyController businessPolicyController(
            BusinessPolicyService businessPolicyService,
            BusinessMetadataService businessMetadataService) {
        return new BusinessPolicyController(businessPolicyService, businessMetadataService);
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
    public PolicyBuilderController policyBuilderController(
            PolicyBuilderService policyBuilderService,
            UserManagementService userManagementService,
            GroupService groupService,
            RoleService roleService,
            PermissionCatalogService permissionCatalogService,
            ConditionTemplateRepository conditionTemplateRepository,
            ManagedResourceRepository managedResourceRepository,
            ObjectMapper objectMapper,
            PermissionService permissionService,
            ModelMapper modelMapper,
            ConditionCompatibilityService conditionCompatibilityService) {
        return new PolicyBuilderController(
                policyBuilderService, userManagementService, groupService, roleService,
                permissionCatalogService, conditionTemplateRepository, managedResourceRepository,
                objectMapper, permissionService, modelMapper, conditionCompatibilityService);
    }
}
