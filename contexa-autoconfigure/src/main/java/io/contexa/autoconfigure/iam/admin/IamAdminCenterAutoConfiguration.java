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
package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacore.infra.redis.PolicyReloadBroadcaster;
import org.springframework.beans.factory.ObjectProvider;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.center.PolicyCenterController;
import io.contexa.contexaiam.admin.web.center.PolicyCenterOperationsController;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterAnalysisService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterCommandService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterPageService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterQueryService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.SecuritySpelRepository;
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
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

@AutoConfiguration
@AutoConfigureAfter({
        IamAdminAuthAutoConfiguration.class
})
public class IamAdminCenterAutoConfiguration {

    @Bean(name = "contexaPolicyCenterQueryService")
    @ConditionalOnMissingBean
    public PolicyCenterQueryService policyCenterQueryService(
            ResourceRegistryService contexaResourceRegistryService,
            RoleService contexaRoleService,
            PermissionCatalogService contexaPermissionCatalogService,
            ConditionTemplateRepository conditionTemplateRepository,
            ManagedResourceRepository managedResourceRepository,
            SecuritySpelRepository securitySpelRepository,
            PolicyRepository policyRepository,
            PolicyService contexaPolicyService,
            PolicyVersionService contexaPolicyVersionService) {
        return new PolicyCenterQueryService(
                contexaResourceRegistryService,
                contexaRoleService,
                contexaPermissionCatalogService,
                conditionTemplateRepository,
                managedResourceRepository,
                securitySpelRepository,
                policyRepository,
                contexaPolicyService,
                contexaPolicyVersionService);
    }

    @Bean(name = "contexaPolicyCenterPageService")
    @ConditionalOnMissingBean
    public PolicyCenterPageService policyCenterPageService(
            ResourceRegistryService contexaResourceRegistryService,
            PolicyService contexaPolicyService,
            PolicyCombiningProperties policyCombiningProperties) {
        return new PolicyCenterPageService(
                contexaResourceRegistryService,
                contexaPolicyService,
                policyCombiningProperties);
    }

    @Bean(name = "contexaPolicyCenterCommandService")
    @ConditionalOnMissingBean
    public PolicyCenterCommandService policyCenterCommandService(
            ResourceRegistryService contexaResourceRegistryService,
            PolicyService contexaPolicyService,
            PolicyRepository policyRepository,
            RoleService contexaRoleService,
            BusinessPolicyService contexaBusinessPolicyService,
            ManagedResourceRepository managedResourceRepository,
            PermissionRepository permissionRepository,
            PolicyValidationService contexaPolicyValidationService,
            PolicyEnrichmentService contexaPolicyEnrichmentService,
            PolicyVersionService contexaPolicyVersionService,
            CustomDynamicAuthorizationManager authorizationManager,
            CentralAuditFacade contexaCentralAuditFacade,
            MessageSource messageSource,
            ObjectProvider<PolicyReloadBroadcaster> policyReloadBroadcasterProvider,
            @Qualifier("contexaTransactionManager") ObjectProvider<PlatformTransactionManager> transactionManagerProvider) {
        PolicyCenterCommandService service = new PolicyCenterCommandService(
                contexaResourceRegistryService,
                contexaPolicyService,
                policyRepository,
                contexaRoleService,
                contexaBusinessPolicyService,
                managedResourceRepository,
                permissionRepository,
                contexaPolicyValidationService,
                contexaPolicyEnrichmentService,
                contexaPolicyVersionService,
                authorizationManager,
                contexaCentralAuditFacade,
                messageSource);
        policyReloadBroadcasterProvider.ifAvailable(service::setPolicyReloadBroadcaster);
        transactionManagerProvider.ifAvailable(manager -> {
            TransactionTemplate item = new TransactionTemplate(manager);
            item.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
            service.setItemTransactions(item);
        });
        return service;
    }

    @Bean(name = "contexaPolicyCenterAnalysisService")
    @ConditionalOnMissingBean
    public PolicyCenterAnalysisService policyCenterAnalysisService(
            PolicyService contexaPolicyService,
            PolicyValidationService contexaPolicyValidationService,
            PermissionRepository permissionRepository,
            PolicyMatrixService contexaPolicyMatrixService) {
        return new PolicyCenterAnalysisService(
                contexaPolicyService,
                contexaPolicyValidationService,
                permissionRepository,
                contexaPolicyMatrixService);
    }

    @Bean(name = "contexaPolicyCenterController")
    @ConditionalOnMissingBean
    public PolicyCenterController policyCenterController(
            MessageSource messageSource,
            PolicyCenterPageService contexaPolicyCenterPageService,
            PolicyCenterQueryService contexaPolicyCenterQueryService,
            PolicyCenterCommandService contexaPolicyCenterCommandService,
            PolicyCenterAnalysisService contexaPolicyCenterAnalysisService) {
        return new PolicyCenterController(
                messageSource,
                contexaPolicyCenterPageService,
                contexaPolicyCenterQueryService,
                contexaPolicyCenterCommandService,
                contexaPolicyCenterAnalysisService);
    }

    @Bean(name = "contexaPolicyCenterOperationsController")
    @ConditionalOnMissingBean
    public PolicyCenterOperationsController policyCenterOperationsController(
            MessageSource messageSource,
            PolicyCenterQueryService contexaPolicyCenterQueryService,
            PolicyCenterCommandService contexaPolicyCenterCommandService,
            PolicyCenterAnalysisService contexaPolicyCenterAnalysisService) {
        return new PolicyCenterOperationsController(
                messageSource,
                contexaPolicyCenterQueryService,
                contexaPolicyCenterCommandService,
                contexaPolicyCenterAnalysisService);
    }
}

