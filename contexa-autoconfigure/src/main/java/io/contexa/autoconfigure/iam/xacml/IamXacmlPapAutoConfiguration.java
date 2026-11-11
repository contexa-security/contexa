/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.autoconfigure.iam.xacml;

import org.springframework.beans.factory.BeanFactory;
import io.contexa.autoconfigure.core.ContexaOwnBeans;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.authority.AuthorityResolver;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.infra.redis.PolicyReloadBroadcaster;
import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsRuntimeApplier;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.common.event.service.IntegrationEventBus;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.PolicyTemplateRepository;
import io.contexa.contexaiam.repository.PolicyVersionRepository;
import io.contexa.contexaiam.repository.SecuritySpelRepository;
import io.contexa.contexaiam.resource.service.ConditionCompatibilityService;
import io.contexa.contexaiam.security.xacml.pap.analysis.AIPolicyValidator;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyConflictAnalyzer;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyDuplicateDetector;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyImpactAnalyzer;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyMatrixService;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicySimulator;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pap.controller.PolicyApiController;
import io.contexa.contexaiam.security.xacml.pap.controller.PolicyBuilderController;
import io.contexa.contexaiam.security.xacml.pap.controller.PolicyController;
import io.contexa.contexaiam.security.xacml.pap.service.*;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import io.contexa.contexaiam.security.xacml.pdp.translator.PolicyTranslator;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import org.modelmapper.ModelMapper;
import org.redisson.api.RedissonClient;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.MessageSource;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;


@AutoConfiguration
@AutoConfigureAfter(name = {
        "org.redisson.spring.starter.RedissonAutoConfiguration",
        "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration",
        "io.contexa.contexacommon.config.redis.CommonRedisAutoConfiguration",
        "io.contexa.autoconfigure.core.infra.CoreInfrastructureAutoConfiguration"
})
public class IamXacmlPapAutoConfiguration {

    
    @Bean(name = "contexaPolicyEnrichmentService")
    @ConditionalOnMissingBean
    public PolicyEnrichmentService policyEnrichmentService(PolicyTranslator contexaPolicyTranslator) {
        return new PolicyEnrichmentService(contexaPolicyTranslator);
    }

    @Bean(name = "contexaPolicySynchronizationService")
    @ConditionalOnMissingBean
    public PolicySynchronizationService policySynchronizationService(
            PolicyRepository policyRepository,
            RoleRepository roleRepository,
            PolicyService contexaPolicyService) {
        return new PolicySynchronizationService(policyRepository, roleRepository, contexaPolicyService);
    }

    @Bean(name = "contexaPolicyConflictAnalyzer")
    @ConditionalOnMissingBean
    public PolicyConflictAnalyzer policyConflictAnalyzer(PolicyRepository policyRepository,
                                                         MessageSource messageSource) {
        return new PolicyConflictAnalyzer(policyRepository, messageSource);
    }

    @Bean(name = "contexaPolicyDuplicateDetector")
    @ConditionalOnMissingBean
    public PolicyDuplicateDetector policyDuplicateDetector(
            PolicyRepository policyRepository,
            BeanFactory beanFactory,
            MessageSource messageSource) {
        return new PolicyDuplicateDetector(policyRepository, ContexaOwnBeans.roleHierarchy(beanFactory), messageSource);
    }

    @Bean(name = "contexaPolicyValidationService")
    @ConditionalOnMissingBean
    public PolicyValidationService policyValidationService(
            PolicyConflictAnalyzer contexaPolicyConflictAnalyzer,
            PolicyDuplicateDetector contexaPolicyDuplicateDetector,
            PolicyRepository policyRepository,
            MessageSource messageSource) {
        return new PolicyValidationService(contexaPolicyConflictAnalyzer, contexaPolicyDuplicateDetector, policyRepository, messageSource);
    }

    @Bean(name = "contexaPolicyImpactAnalyzer")
    @ConditionalOnMissingBean
    public PolicyImpactAnalyzer policyImpactAnalyzer(
            UserRepository userRepository,
            PolicyRepository policyRepository,
            BeanFactory beanFactory,
            AuthorityResolver contexaAuthorityResolver) {
        return new PolicyImpactAnalyzer(userRepository, policyRepository, ContexaOwnBeans.roleHierarchy(beanFactory), contexaAuthorityResolver);
    }

    @Bean(name = "contexaPolicySimulator")
    @ConditionalOnMissingBean
    public PolicySimulator policySimulator(
            UserRepository userRepository,
            PolicyRepository policyRepository,
            BeanFactory beanFactory,
            ObjectProvider<PolicyCombiningEvaluator> policyCombiningEvaluator,
            ObjectProvider<PolicyCombiningProperties> policyCombiningProperties) {
        return new PolicySimulator(userRepository, policyRepository, ContexaOwnBeans.roleHierarchy(beanFactory),
                policyCombiningEvaluator.getIfAvailable(PolicyCombiningEvaluator::new),
                policyCombiningProperties.getIfAvailable(PolicyCombiningProperties::new));
    }

    @Bean(name = "contexaPolicyMatrixService")
    @ConditionalOnMissingBean
    public PolicyMatrixService policyMatrixService(
            PolicyRepository policyRepository,
            RoleRepository roleRepository,
            BeanFactory beanFactory) {
        return new PolicyMatrixService(policyRepository, roleRepository, ContexaOwnBeans.roleHierarchy(beanFactory));
    }

    @Bean(name = "contexaAiPolicyValidator")
    @ConditionalOnMissingBean
    public AIPolicyValidator aiPolicyValidator(
            RoleRepository roleRepository,
            PermissionRepository permissionRepository,
            PolicyConflictAnalyzer contexaPolicyConflictAnalyzer,
            PolicyDuplicateDetector contexaPolicyDuplicateDetector,
            MessageSource messageSource) {
        return new AIPolicyValidator(roleRepository, permissionRepository,
                contexaPolicyConflictAnalyzer, contexaPolicyDuplicateDetector, messageSource);
    }

    @Bean(name = "contexaPolicyVersionService")
    @ConditionalOnMissingBean
    public PolicyVersionService policyVersionService(
            PolicyVersionRepository policyVersionRepository,
            @Qualifier("contexaObjectMapper") ObjectMapper objectMapper,
            @Qualifier("contexaModelMapper") ModelMapper contexaModelMapper) {
        return new PolicyVersionService(policyVersionRepository, objectMapper, contexaModelMapper);
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.redisson.api.RedissonClient")
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
    static class RedissonPapConfiguration {

        /** On Contexa's own Redisson client: an application's own client carries none of Contexa's signals. */
        @Bean(name = "contexaPolicyReloadBroadcaster")
        @ConditionalOnMissingBean
        @ConditionalOnBean(name = "contexaRedissonClient")
        public PolicyReloadBroadcaster policyReloadBroadcaster(
                @Qualifier("contexaRedissonClient") RedissonClient contexaRedissonClient,
                PolicyRetrievalPoint policyRetrievalPoint,
                CustomDynamicAuthorizationManager authorizationManager,
                ObjectProvider<SystemSettingsRuntimeApplier> runtimeApplierProvider) {
            return new PolicyReloadBroadcaster(contexaRedissonClient, () -> {
                runtimeApplierProvider.ifAvailable(SystemSettingsRuntimeApplier::applyPolicyDecisionSettings);
                policyRetrievalPoint.clearUrlPoliciesCache();
                policyRetrievalPoint.clearMethodPoliciesCache();
                authorizationManager.reload();
            });
        }
    }

    @Bean(name = "contexaDefaultPolicyService")
    @ConditionalOnMissingBean
    public PolicyService defaultPolicyService(
            PolicyRepository policyRepository,
            PolicyRetrievalPoint policyRetrievalPoint,
            CustomDynamicAuthorizationManager authorizationManager,
            PolicyEnrichmentService contexaPolicyEnrichmentService,
            IntegrationEventBus eventBus,
            PermissionRepository permissionRepository,
            ManagedResourceRepository managedResourceRepository,
            CentralAuditFacade contexaCentralAuditFacade,
            PolicyConflictAnalyzer contexaPolicyConflictAnalyzer,
            PolicyValidationService contexaPolicyValidationService,
            PolicyVersionService contexaPolicyVersionService,
            PolicyImpactAnalyzer contexaPolicyImpactAnalyzer,
            PolicySimulator contexaPolicySimulator,
            MessageSource messageSource,
            AIPolicyValidator contexaAiPolicyValidator,
            ObjectProvider<PolicyReloadBroadcaster> policyReloadBroadcasterProvider) {
        DefaultPolicyService service = new DefaultPolicyService(
                policyRepository, policyRetrievalPoint, authorizationManager,
                contexaPolicyEnrichmentService, eventBus, permissionRepository, managedResourceRepository,
                contexaCentralAuditFacade, contexaPolicyConflictAnalyzer, contexaPolicyValidationService,
                contexaPolicyVersionService, contexaPolicyImpactAnalyzer, contexaPolicySimulator, messageSource, contexaAiPolicyValidator);
        policyReloadBroadcasterProvider.ifAvailable(service::setPolicyReloadBroadcaster);
        return service;
    }

    @Bean(name = "contexaPolicyBuilderService")
    @ConditionalOnMissingBean
    public PolicyBuilderService policyBuilderService(
            PolicyRepository policyRepository,
            UserRepository userRepository,
            PermissionRepository permissionRepository,
            PolicyTemplateRepository policyTemplateRepository,
            PolicyService contexaPolicyService,
            @Qualifier("contexaModelMapper") ModelMapper contexaModelMapper,
            @Qualifier("contexaObjectMapper") ObjectMapper objectMapper,
            PolicyConflictAnalyzer contexaPolicyConflictAnalyzer) {
        return new PolicyBuilderServiceImpl(
                policyRepository, userRepository, permissionRepository,
                policyTemplateRepository, contexaPolicyService, contexaModelMapper, objectMapper,
                contexaPolicyConflictAnalyzer);
    }

    @Bean(name = "contexaBusinessPolicyService")
    @ConditionalOnMissingBean
    public BusinessPolicyService businessPolicyService(
            PolicyRepository policyRepository,
            @Lazy RoleService contexaRoleService,
            RoleRepository roleRepository,
            PermissionRepository permissionRepository,
            ConditionTemplateRepository conditionTemplateRepository,
            PolicyEnrichmentService contexaPolicyEnrichmentService,
            CustomDynamicAuthorizationManager authorizationManager,
            SecuritySpelRepository securitySpelRepository,
            CentralAuditFacade contexaCentralAuditFacade,
            PolicyConflictAnalyzer contexaPolicyConflictAnalyzer,
            PolicyVersionService contexaPolicyVersionService,
            MessageSource messageSource,
            ObjectProvider<PolicyReloadBroadcaster> policyReloadBroadcasterProvider) {
        BusinessPolicyServiceImpl service = new BusinessPolicyServiceImpl(
                policyRepository, contexaRoleService, roleRepository, permissionRepository,
                conditionTemplateRepository, contexaPolicyEnrichmentService, authorizationManager,
                securitySpelRepository, contexaCentralAuditFacade, contexaPolicyConflictAnalyzer,
                contexaPolicyVersionService, messageSource);
        policyReloadBroadcasterProvider.ifAvailable(service::setPolicyReloadBroadcaster);
        return service;
    }

    @Bean(name = "contexaPolicyController")
    @ConditionalOnMissingBean
    public PolicyController policyController(
            PolicyService contexaPolicyService,
            @Qualifier("contexaModelMapper") ModelMapper contexaModelMapper,
            MessageSource messageSource) {
        return new PolicyController(contexaPolicyService, contexaModelMapper, messageSource);
    }

    @Bean(name = "contexaPolicyApiController")
    @ConditionalOnMissingBean
    public PolicyApiController policyApiController(
            BusinessPolicyService contexaBusinessPolicyService,
            @Qualifier("contexaModelMapper") ModelMapper contexaModelMapper) {
        return new PolicyApiController(contexaBusinessPolicyService, contexaModelMapper);
    }

    @Bean(name = "contexaPolicyBuilderController")
    @ConditionalOnMissingBean
    public PolicyBuilderController policyBuilderController(
            RoleService contexaRoleService,
            PermissionCatalogService contexaPermissionCatalogService,
            ConditionTemplateRepository conditionTemplateRepository,
            ManagedResourceRepository managedResourceRepository,
            @Qualifier("contexaObjectMapper") ObjectMapper objectMapper,
            PermissionService contexaPermissionService,
            ConditionCompatibilityService contexaConditionCompatibilityService) {
        return new PolicyBuilderController(
                contexaRoleService, contexaPermissionCatalogService, conditionTemplateRepository, managedResourceRepository,
                objectMapper, contexaPermissionService, contexaConditionCompatibilityService);
    }
}

