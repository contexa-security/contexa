package io.contexa.autoconfigure.iam.xacml;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.MessageSource;
import io.contexa.contexacommon.security.authority.AuthorityResolver;
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
import io.contexa.contexaiam.security.xacml.pap.analysis.AIPolicyValidator;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyConflictAnalyzer;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyDuplicateDetector;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyImpactAnalyzer;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyMatrixService;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicySimulator;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.repository.PolicyVersionRepository;
import io.contexa.contexaiam.security.xacml.pap.service.*;
import io.contexa.contexaiam.security.xacml.pdp.translator.PolicyTranslator;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexacore.infra.redis.PolicyReloadBroadcaster;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import org.modelmapper.ModelMapper;
import org.redisson.api.RedissonClient;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Lazy;


@AutoConfiguration
@AutoConfigureAfter(name = {
        "org.redisson.spring.starter.RedissonAutoConfiguration",
        "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration",
        "io.contexa.contexacommon.config.redis.CommonRedisAutoConfiguration"
})
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
    public PolicyConflictAnalyzer policyConflictAnalyzer(PolicyRepository policyRepository,
                                                         MessageSource messageSource) {
        return new PolicyConflictAnalyzer(policyRepository, messageSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyDuplicateDetector policyDuplicateDetector(
            PolicyRepository policyRepository,
            RoleHierarchy roleHierarchy,
            MessageSource messageSource) {
        return new PolicyDuplicateDetector(policyRepository, roleHierarchy, messageSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyValidationService policyValidationService(
            PolicyConflictAnalyzer policyConflictAnalyzer,
            PolicyDuplicateDetector policyDuplicateDetector,
            PolicyRepository policyRepository,
            MessageSource messageSource) {
        return new PolicyValidationService(policyConflictAnalyzer, policyDuplicateDetector, policyRepository, messageSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyImpactAnalyzer policyImpactAnalyzer(
            UserRepository userRepository,
            PolicyRepository policyRepository,
            RoleHierarchy roleHierarchy,
            AuthorityResolver authorityResolver) {
        return new PolicyImpactAnalyzer(userRepository, policyRepository, roleHierarchy, authorityResolver);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicySimulator policySimulator(
            UserRepository userRepository,
            PolicyRepository policyRepository,
            RoleHierarchy roleHierarchy) {
        return new PolicySimulator(userRepository, policyRepository, roleHierarchy);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyMatrixService policyMatrixService(
            PolicyRepository policyRepository,
            RoleRepository roleRepository,
            RoleHierarchy roleHierarchy) {
        return new PolicyMatrixService(policyRepository, roleRepository, roleHierarchy);
    }

    @Bean
    @ConditionalOnMissingBean
    public AIPolicyValidator aiPolicyValidator(
            RoleRepository roleRepository,
            PermissionRepository permissionRepository,
            PolicyConflictAnalyzer policyConflictAnalyzer,
            PolicyDuplicateDetector policyDuplicateDetector,
            MessageSource messageSource) {
        return new AIPolicyValidator(roleRepository, permissionRepository,
                policyConflictAnalyzer, policyDuplicateDetector, messageSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyVersionService policyVersionService(
            PolicyVersionRepository policyVersionRepository,
            ObjectMapper objectMapper,
            ModelMapper modelMapper) {
        return new PolicyVersionService(policyVersionRepository, objectMapper, modelMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(RedissonClient.class)
    public PolicyReloadBroadcaster policyReloadBroadcaster(
            RedissonClient redissonClient,
            PolicyRetrievalPoint policyRetrievalPoint,
            CustomDynamicAuthorizationManager authorizationManager) {
        return new PolicyReloadBroadcaster(redissonClient, () -> {
            policyRetrievalPoint.clearUrlPoliciesCache();
            policyRetrievalPoint.clearMethodPoliciesCache();
            authorizationManager.reload();
        });
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyService defaultPolicyService(
            PolicyRepository policyRepository,
            PolicyRetrievalPoint policyRetrievalPoint,
            CustomDynamicAuthorizationManager authorizationManager,
            PolicyEnrichmentService policyEnrichmentService,
            IntegrationEventBus eventBus,
            PermissionRepository permissionRepository,
            ManagedResourceRepository managedResourceRepository,
            io.contexa.contexacore.autonomous.audit.CentralAuditFacade centralAuditFacade,
            PolicyConflictAnalyzer policyConflictAnalyzer,
            PolicyValidationService policyValidationService,
            PolicyVersionService policyVersionService,
            PolicyImpactAnalyzer policyImpactAnalyzer,
            PolicySimulator policySimulator,
            MessageSource messageSource,
            AIPolicyValidator aiPolicyValidator,
            ObjectProvider<PolicyReloadBroadcaster> policyReloadBroadcasterProvider) {
        DefaultPolicyService service = new DefaultPolicyService(
                policyRepository, policyRetrievalPoint, authorizationManager,
                policyEnrichmentService, eventBus, permissionRepository, managedResourceRepository,
                centralAuditFacade, policyConflictAnalyzer, policyValidationService,
                policyVersionService, policyImpactAnalyzer, policySimulator, messageSource, aiPolicyValidator);
        policyReloadBroadcasterProvider.ifAvailable(service::setPolicyReloadBroadcaster);
        return service;
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
            ObjectMapper objectMapper,
            PolicyConflictAnalyzer policyConflictAnalyzer) {
        return new PolicyBuilderServiceImpl(
                policyRepository, userRepository, permissionRepository,
                policyTemplateRepository, policyService, modelMapper, objectMapper,
                policyConflictAnalyzer);
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
            CustomDynamicAuthorizationManager authorizationManager,
            io.contexa.contexaiam.repository.SecuritySpelRepository securitySpelRepository,
            io.contexa.contexacore.autonomous.audit.CentralAuditFacade centralAuditFacade,
            PolicyConflictAnalyzer policyConflictAnalyzer,
            PolicyVersionService policyVersionService,
            MessageSource messageSource) {
        return new BusinessPolicyServiceImpl(
                policyRepository, roleService, roleRepository, permissionRepository,
                conditionTemplateRepository, policyEnrichmentService, authorizationManager,
                securitySpelRepository, centralAuditFacade, policyConflictAnalyzer,
                policyVersionService, messageSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyController policyController(
            PolicyService policyService,
            ModelMapper modelMapper,
            MessageSource messageSource) {
        return new PolicyController(policyService, modelMapper, messageSource);
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

