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
package io.contexa.autoconfigure.core;

import io.contexa.autoconfigure.ai.AiBridgeConfiguration;
import io.contexa.autoconfigure.ai.AiBridgeUserMirrorSyncAutoConfiguration;
import io.contexa.autoconfigure.core.autonomous.CoreSaasForwardingAutoConfiguration;
import io.contexa.autoconfigure.hostapp.HostOrderRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurationPackage;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.data.jpa.JpaRepositoriesAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Verifies that beans guarded by {@code @ConditionalOnBean(<Contexa repository>)} are created when the
 * Contexa repositories are registered. The contexts are lazily initialized so that only bean definitions
 * (the result of condition evaluation) are checked. The Contexa EntityManagerFactory is still bootstrapped
 * because it is LoadTimeWeaverAware, so it points at an unreachable PostgreSQL URL whose dialect is inferred
 * without JDBC metadata, as in {@link CoreDataAutoConfigurationTest}.
 */
class ContexaRepositoryBackedBeansTest {

    private static final String[] REPOSITORY_BACKED_BEANS = {
            "bridgeUserMirrorSyncService",
            "baselineSignalAggregationService",
            "saasBaselineSignalDispatcher",
            "saasBaselineSignalScheduler",
            "modelPerformanceTelemetryCollector",
            "modelPerformanceTelemetryObserver",
            "saasModelPerformanceTelemetryDispatcher",
            "saasModelPerformanceTelemetryScheduler",
            "saasPromptContextAuditDispatcher",
            "promptContextAuditForwardingService",
            "saasPromptContextAuditRetryScheduler",
            "saasDecisionDispatcher",
            "saasDecisionOutboxService",
            "saasOutboxRetryScheduler",
            "saasForwardingHandler",
            "saasDecisionFeedbackDispatcher",
            "saasDecisionFeedbackOutboxService",
            "saasDecisionFeedbackRetryScheduler",
            "saasThreatOutcomeDispatcher",
            "saasThreatOutcomeOutboxService",
            "saasThreatOutcomeRetryScheduler"
    };

    private static final String[] CONTEXA_DATASOURCE_PROPERTIES = {
            "contexa.datasource.url=jdbc:postgresql://127.0.0.1:1/contexa",
            "contexa.datasource.driver-class-name=org.postgresql.Driver",
            "contexa.jpa.hibernate.ddl-auto=none"
    };

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withInitializer(ContexaRepositoryBackedBeansTest::lazyInitializeAllBeans)
            .withUserConfiguration(AiBridgeConfiguration.class)
            .withConfiguration(AutoConfigurations.of(
                    CoreSaasForwardingAutoConfiguration.class,
                    AiBridgeUserMirrorSyncAutoConfiguration.class,
                    CoreDataAutoConfiguration.class))
            .withBean(PlatformConfig.class, () -> PlatformConfig.builder().build())
            .withBean(BaselineDataStore.class, () -> mock(BaselineDataStore.class))
            .withPropertyValues(CONTEXA_DATASOURCE_PROPERTIES)
            .withPropertyValues(
                    "contexa.saas.enabled=true",
                    "contexa.saas.baseline-signal.enabled=true",
                    "contexa.saas.decision-feedback.enabled=true",
                    "contexa.saas.threat-outcome.enabled=true",
                    "contexa.saas.performance-telemetry.enabled=true",
                    "contexa.saas.prompt-context-audit.enabled=true");

    @Test
    @DisplayName("Repository-backed bridge and SaaS beans are created when Contexa repositories are registered")
    void repositoryBackedBeansAreCreatedWhenContexaRepositoriesAreRegistered() {
        contextRunner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBeanFactory().getBeanDefinitionNames())
                    .contains("contexaUserRepository", "contexaBridgeUserProfileRepository")
                    .contains(REPOSITORY_BACKED_BEANS);
        });
    }

    @Test
    @DisplayName("Repository-backed bridge and SaaS beans are not created when Contexa repositories are disabled")
    void repositoryBackedBeansAreNotCreatedWhenContexaRepositoriesAreDisabled() {
        contextRunner.withPropertyValues("contexa.jpa.repositories.enabled=false")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBeanFactory().getBeanDefinitionNames())
                            .contains("bridgeRuntimeSupport", "saasDecisionHttpClient")
                            .doesNotContain("contexaUserRepository", "contexaBridgeUserProfileRepository")
                            .doesNotContain(REPOSITORY_BACKED_BEANS);
                });
    }

    @Test
    @DisplayName("Spring Boot still registers the application's repositories next to the Contexa repositories")
    void applicationRepositoriesAreStillRegisteredBySpringBoot() {
        new ApplicationContextRunner()
                .withInitializer(ContexaRepositoryBackedBeansTest::lazyInitializeAllBeans)
                .withUserConfiguration(HostApplicationPackage.class)
                .withConfiguration(AutoConfigurations.of(
                        CoreDataAutoConfiguration.class,
                        JpaRepositoriesAutoConfiguration.class))
                .withBean(PlatformConfig.class, () -> PlatformConfig.builder().build())
                .withBean(DataSource.class, () -> mock(DataSource.class))
                .withPropertyValues(CONTEXA_DATASOURCE_PROPERTIES)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBeanFactory().getBeanNamesForType(HostOrderRepository.class, true, false))
                            .hasSize(1);
                    assertThat(List.of(context.getBeanFactory().getBeanNamesForType(UserRepository.class, true, false)))
                            .containsExactly("contexaUserRepository");
                });
    }

    private static void lazyInitializeAllBeans(ConfigurableApplicationContext context) {
        context.addBeanFactoryPostProcessor(beanFactory -> {
            for (String beanName : beanFactory.getBeanDefinitionNames()) {
                beanFactory.getBeanDefinition(beanName).setLazyInit(true);
            }
        });
    }

    @Configuration(proxyBeanMethods = false)
    @AutoConfigurationPackage(basePackageClasses = HostOrderRepository.class)
    static class HostApplicationPackage {
    }
}
