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

import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
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
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyMatrixService;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pap.service.BusinessPolicyService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyEnrichmentService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyVersionService;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.MessageSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

@DisplayName("IamAdminCenterAutoConfiguration")
class IamAdminCenterAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(IamAdminCenterAutoConfiguration.class))
            .withBean(PlatformConfig.class, () -> PlatformConfig.builder().build())
            .withBean(ResourceRegistryService.class, () -> mock(ResourceRegistryService.class))
            .withBean(RoleService.class, () -> mock(RoleService.class))
            .withBean(PermissionCatalogService.class, () -> mock(PermissionCatalogService.class))
            .withBean(ConditionTemplateRepository.class, () -> mock(ConditionTemplateRepository.class))
            .withBean(ManagedResourceRepository.class, () -> mock(ManagedResourceRepository.class))
            .withBean(SecuritySpelRepository.class, () -> mock(SecuritySpelRepository.class))
            .withBean(PolicyRepository.class, () -> mock(PolicyRepository.class))
            .withBean(PolicyService.class, () -> mock(PolicyService.class))
            .withBean(PolicyVersionService.class, () -> mock(PolicyVersionService.class))
            .withBean(PolicyCombiningProperties.class, PolicyCombiningProperties::new)
            .withBean(BusinessPolicyService.class, () -> mock(BusinessPolicyService.class))
            .withBean(PermissionRepository.class, () -> mock(PermissionRepository.class))
            .withBean(PolicyValidationService.class, () -> mock(PolicyValidationService.class))
            .withBean(PolicyEnrichmentService.class, () -> mock(PolicyEnrichmentService.class))
            .withBean(CustomDynamicAuthorizationManager.class, () -> mock(CustomDynamicAuthorizationManager.class))
            .withBean(CentralAuditFacade.class, () -> mock(CentralAuditFacade.class))
            .withBean(PolicyMatrixService.class, () -> mock(PolicyMatrixService.class))
            .withBean(MessageSource.class, () -> mock(MessageSource.class));

    @Nested
    @DisplayName("Policy center beans")
    class PolicyCenterBeans {

        @Test
        @DisplayName("Should register policy center services and controller without component scanning")
        void shouldRegisterPolicyCenterBeans() {
            contextRunner.run(context -> {
                assertThat(context).hasSingleBean(PolicyCenterPageService.class);
                assertThat(context).hasSingleBean(PolicyCenterQueryService.class);
                assertThat(context).hasSingleBean(PolicyCenterCommandService.class);
                assertThat(context).hasSingleBean(PolicyCenterAnalysisService.class);
                assertThat(context).hasSingleBean(PolicyCenterController.class);
            });
        }
    }

    @Nested
    @DisplayName("ConditionalOnMissingBean behavior")
    class ConditionalBehavior {

        @Test
        @DisplayName("Should not override custom PolicyCenterCommandService")
        void shouldNotOverrideCustomCommandService() {
            PolicyCenterCommandService custom = mock(PolicyCenterCommandService.class);

            contextRunner
                    .withBean(PolicyCenterCommandService.class, () -> custom)
                    .run(context -> {
                        assertThat(context).hasSingleBean(PolicyCenterCommandService.class);
                        assertThat(context.getBean(PolicyCenterCommandService.class)).isSameAs(custom);
                    });
        }
    }
}
