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

import io.contexa.autoconfigure.identity.IamSeedDataAutoConfiguration;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacommon.entity.AdminMenu;
import io.contexa.contexacommon.repository.AdminMenuRepository;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.web.menu.service.AdminMenuService;
import io.contexa.contexaiam.admin.web.monitoring.service.DashboardService;
import io.contexa.contexaiam.admin.web.monitoring.service.PermissionMatrixService;
import io.contexa.contexaiam.admin.web.monitoring.service.SecurityScoreCalculator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.MessageSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("IamAdminMonitoringAutoConfiguration")
class IamAdminMonitoringAutoConfigurationTest {

    private static final String IAM_SEED_DATA_INITIALIZER_BEAN = "iamSeedDataInitializer";

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    IamAdminMonitoringAutoConfiguration.class,
                    IamSeedDataAutoConfiguration.class))
            .withBean(ContexaProperties.class, ContexaProperties::new)
            .withBean(SecurityZeroTrustProperties.class, SecurityZeroTrustProperties::new)
            .withBean(AdminMenuRepository.class, IamAdminMonitoringAutoConfigurationTest::adminMenuRepository)
            .withBean(AuditLogRepository.class, () -> mock(AuditLogRepository.class))
            .withBean(RoleRepository.class, () -> mock(RoleRepository.class))
            .withBean(DashboardService.class, () -> mock(DashboardService.class))
            .withBean(SecurityScoreCalculator.class, () -> mock(SecurityScoreCalculator.class))
            .withBean(PermissionMatrixService.class, () -> mock(PermissionMatrixService.class))
            .withBean(MessageSource.class, () -> mock(MessageSource.class));

    @Test
    @DisplayName("admin menu service should start without the IAM seed initializer when seeding is disabled")
    void adminMenuServiceStartsWhenIamSeedIsDisabled() {
        contextRunner
                .withPropertyValues("contexa.iam.seed.enabled=false")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(IAM_SEED_DATA_INITIALIZER_BEAN);
                    assertThat(context).hasSingleBean(AdminMenuService.class);
                    String[] dependsOn = context.getBeanFactory()
                            .getBeanDefinition("adminMenuService")
                            .getDependsOn();
                    assertThat(dependsOn == null ? new String[0] : dependsOn)
                            .doesNotContain(IAM_SEED_DATA_INITIALIZER_BEAN);
                });
    }

    @Test
    @DisplayName("admin menu service should wait for the IAM seed initializer when it is registered")
    void adminMenuServiceDependsOnIamSeedInitializerWhenPresent() {
        contextRunner
                .withBean(IAM_SEED_DATA_INITIALIZER_BEAN, InitializingBean.class, () -> () -> {
                })
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(AdminMenuService.class);
                    assertThat(context.getBeanFactory()
                            .getBeanDefinition("adminMenuService")
                            .getDependsOn())
                            .contains(IAM_SEED_DATA_INITIALIZER_BEAN);
                });
    }

    private static AdminMenuRepository adminMenuRepository() {
        AdminMenuRepository repository = mock(AdminMenuRepository.class);
        when(repository.save(any(AdminMenu.class))).thenAnswer(invocation -> invocation.getArgument(0));
        return repository;
    }
}
