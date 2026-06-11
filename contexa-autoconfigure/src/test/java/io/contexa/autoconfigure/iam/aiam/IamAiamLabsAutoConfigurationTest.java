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
package io.contexa.autoconfigure.iam.aiam;

import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.impl.RoleHierarchyService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.aiam.labs.condition.ConditionTemplateGenerationLab;
import io.contexa.contexaiam.aiam.labs.data.IAMDataCollectionService;
import io.contexa.contexaiam.aiam.labs.data.PolicyGenerationCollectionService;
import io.contexa.contexaiam.aiam.labs.policy.AdvancedPolicyGenerationLab;
import io.contexa.contexaiam.aiam.labs.policy.PolicyGenerationVectorService;
import io.contexa.contexaiam.aiam.labs.resource.ResourceNamingLab;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class IamAiamLabsAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(IamAiamLabsAutoConfiguration.class))
            .withBean(PlatformConfig.class, () -> mock(PlatformConfig.class))
            .withBean(RoleService.class, () -> mock(RoleService.class))
            .withBean(PermissionCatalogService.class, () -> mock(PermissionCatalogService.class))
            .withBean(ConditionTemplateRepository.class, () -> mock(ConditionTemplateRepository.class))
            .withBean(PolicyRepository.class, () -> mock(PolicyRepository.class))
            .withBean(RoleHierarchyService.class, () -> mock(RoleHierarchyService.class))
            .withBean(PipelineOrchestrator.class, () -> mock(PipelineOrchestrator.class));

    @Test
    void shouldStartWithoutVectorStoreAndSkipVectorBackedPolicyLab() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(PolicyGenerationCollectionService.class);
            assertThat(context).hasSingleBean(IAMDataCollectionService.class);
            assertThat(context).hasSingleBean(ResourceNamingLab.class);
            assertThat(context).hasSingleBean(ConditionTemplateGenerationLab.class);
            assertThat(context).doesNotHaveBean(PolicyGenerationVectorService.class);
            assertThat(context).doesNotHaveBean(AdvancedPolicyGenerationLab.class);
        });
    }
}
