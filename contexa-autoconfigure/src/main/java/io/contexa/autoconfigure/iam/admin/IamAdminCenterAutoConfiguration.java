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

import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.center.PolicyCenterController;
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
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
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
    public PolicyCenterQueryService policyCenterQueryService(
            ResourceRegistryService resourceRegistryService,
            RoleService roleService,
            PermissionCatalogService permissionCatalogService,
            ConditionTemplateRepository conditionTemplateRepository,
            ManagedResourceRepository managedResourceRepository,
            SecuritySpelRepository securitySpelRepository,
            PolicyRepository policyRepository,
            PolicyService policyService,
            PolicyVersionService policyVersionService) {
        return new PolicyCenterQueryService(
                resourceRegistryService,
                roleService,
                permissionCatalogService,
                conditionTemplateRepository,
                managedResourceRepository,
                securitySpelRepository,
                policyRepository,
                policyService,
                policyVersionService);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyCenterPageService policyCenterPageService(
            ResourceRegistryService resourceRegistryService,
            PolicyService policyService,
            PolicyCombiningProperties policyCombiningProperties) {
        return new PolicyCenterPageService(
                resourceRegistryService,
                policyService,
                policyCombiningProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyCenterCommandService policyCenterCommandService(
            ResourceRegistryService resourceRegistryService,
            PolicyService policyService,
            PolicyRepository policyRepository,
            RoleService roleService,
            BusinessPolicyService businessPolicyService,
            ManagedResourceRepository managedResourceRepository,
            PermissionRepository permissionRepository,
            PolicyValidationService policyValidationService,
            PolicyEnrichmentService policyEnrichmentService,
            PolicyVersionService policyVersionService,
            CustomDynamicAuthorizationManager authorizationManager,
            CentralAuditFacade centralAuditFacade,
            MessageSource messageSource) {
        return new PolicyCenterCommandService(
                resourceRegistryService,
                policyService,
                policyRepository,
                roleService,
                businessPolicyService,
                managedResourceRepository,
                permissionRepository,
                policyValidationService,
                policyEnrichmentService,
                policyVersionService,
                authorizationManager,
                centralAuditFacade,
                messageSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyCenterAnalysisService policyCenterAnalysisService(
            PolicyService policyService,
            PolicyValidationService policyValidationService,
            PermissionRepository permissionRepository,
            PolicyMatrixService policyMatrixService) {
        return new PolicyCenterAnalysisService(
                policyService,
                policyValidationService,
                permissionRepository,
                policyMatrixService);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyCenterController policyCenterController(
            MessageSource messageSource,
            PolicyCenterPageService policyCenterPageService,
            PolicyCenterQueryService policyCenterQueryService,
            PolicyCenterCommandService policyCenterCommandService,
            PolicyCenterAnalysisService policyCenterAnalysisService) {
        return new PolicyCenterController(
                messageSource,
                policyCenterPageService,
                policyCenterQueryService,
                policyCenterCommandService,
                policyCenterAnalysisService);
    }
}

