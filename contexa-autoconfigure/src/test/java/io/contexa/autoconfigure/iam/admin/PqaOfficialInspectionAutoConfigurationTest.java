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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.promptquality.official.application.NoResolutionPromptQualityAssuranceCaseService;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationCurrentResultCoordinator;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationExecutionLockService;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationPromptQualityIssueSynchronizer;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationLedgerWriters;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationSnapshotCleanupRepository;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationSnapshotCommandWriters;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationSnapshotQueryService;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationVerdictQueryService;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityAssuranceCaseService;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityProtectableResourceLookup;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptRuntimeGovernanceDescriptorVerifier;
import io.contexa.contexaiam.admin.promptquality.official.application.RuntimeIssueDiagnosticService;
import io.contexa.contexaiam.admin.promptquality.official.common.OfficialMetricPurposeContractCatalogBootstrap;
import io.contexa.contexaiam.admin.promptquality.official.common.OfficialMetricPurposeContractWriter;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.process.NoOpPromptQualityProcessRunService;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessRunService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.DependsOn;
import org.springframework.jdbc.core.JdbcTemplate;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

class PqaOfficialInspectionAutoConfigurationTest {

    @Test
    void requiredAssuranceRepositoryOwnerEnablesOssAdminBeanDefinitions() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(PqaOfficialInspectionAutoConfiguration.class))
                .withBean(PromptQualityAssuranceCaseService.class,
                        () -> mock(PromptQualityAssuranceCaseService.class))
                .withBean("contexaJdbcTemplate", JdbcTemplate.class,
                        () -> mock(JdbcTemplate.class))
                .withInitializer(context -> context.addBeanFactoryPostProcessor(beanFactory -> {
                    for (String beanName : beanFactory.getBeanDefinitionNames()) {
                        beanFactory.getBeanDefinition(beanName).setLazyInit(true);
                    }
                }))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.containsBeanDefinition("pqaPromptQualityOfficialConsoleApiController"))
                            .isTrue();
                    assertThat(context.containsBeanDefinition("promptQualityRouteModelAdvice"))
                            .isTrue();
                    assertThat(context.containsBeanDefinition("pqaOfficialVerificationExecutionLockService"))
                            .isTrue();
                });
    }

    @Test
    void missingEnterpriseAssuranceRepositoryUsesOssBoundaryAndEnablesPqaBeans() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(PqaOfficialInspectionAutoConfiguration.class))
                .withBean("contexaJdbcTemplate", JdbcTemplate.class,
                        () -> mock(JdbcTemplate.class))
                .withInitializer(context -> context.addBeanFactoryPostProcessor(beanFactory -> {
                    for (String beanName : beanFactory.getBeanDefinitionNames()) {
                        beanFactory.getBeanDefinition(beanName).setLazyInit(true);
                    }
                }))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(PromptQualityAssuranceCaseService.class);
                    assertThat(context.getBean(PromptQualityAssuranceCaseService.class))
                            .isInstanceOf(NoResolutionPromptQualityAssuranceCaseService.class);
                    assertThat(context).hasSingleBean(PromptRuntimeGovernanceDescriptorVerifier.class);
                    assertThat(context).hasSingleBean(PromptQualityProtectableResourceLookup.class);
                    assertThat(context).hasSingleBean(RuntimeIssueDiagnosticService.class);
                    assertThat(context.getBean(PromptRuntimeGovernanceDescriptorVerifier.class)
                            .verify(null, Map.of()).passed()).isTrue();
                    assertThat(context.getBean(PromptQualityProtectableResourceLookup.class)
                            .findBestMatch("/oss/resource", "oss-resource", "GET")).isEmpty();
                    assertThat(context.getBean(RuntimeIssueDiagnosticService.class)
                            .recordIssues("run", "package", List.of(), List.of())).isEmpty();
                    assertThat(context).hasSingleBean(PromptQualityProcessRunService.class);
                    assertThat(context.getBean(PromptQualityProcessRunService.class))
                            .isInstanceOf(NoOpPromptQualityProcessRunService.class);
                    JdbcTemplate jdbcTemplate = context.getBean("contexaJdbcTemplate", JdbcTemplate.class);
                    clearInvocations(jdbcTemplate);
                    context.getBean(OfficialVerificationPromptQualityIssueSynchronizer.class)
                            .synchronize("oss", "package", "run");
                    verifyNoInteractions(jdbcTemplate);
                    assertThat(context.containsBeanDefinition("pqaPromptQualityOfficialConsoleApiController"))
                            .isTrue();
                    assertThat(context.containsBeanDefinition("pqaOfficialVerificationExecutionLockService"))
                            .isTrue();
                });
    }

    @Test
    @DisplayName("OSS PQA contract catalog bootstrap should run after IAM seed initialization")
    void pqaOfficialContractBootstrapDependsOnIamSeedDataInitializer() throws NoSuchMethodException {
        Method method = PqaOfficialInspectionAutoConfiguration.class.getDeclaredMethod(
                "pqaOfficialMetricPurposeContractCatalogBootstrap",
                OfficialMetricPurposeContractWriter.class);

        assertThat(method.getReturnType()).isEqualTo(OfficialMetricPurposeContractCatalogBootstrap.class);
        assertThat(method.getAnnotation(DependsOn.class).value()).containsExactly("iamSeedDataInitializer");
        assertThat(Arrays.asList(method.getAnnotation(ConditionalOnBean.class).name()))
                .contains("iamSeedDataInitializer");
        assertThat(Arrays.asList(method.getAnnotation(ConditionalOnMissingBean.class).name()))
                .contains("officialMetricPurposeContractCatalogBootstrap",
                        "pqaOfficialMetricPurposeContractCatalogBootstrap");
    }

    @Test
    @DisplayName("OSS PQA operator snapshot service should share the bootstrapped contract writer")
    void pqaOperatorSnapshotServiceAcceptsContractCatalogWriterProvider() throws NoSuchMethodException {
        Method method = PqaOfficialInspectionAutoConfiguration.class.getDeclaredMethod(
                "pqaOfficialVerificationOperatorSnapshotService",
                ObjectMapper.class,
                OfficialMetricPurposeContractWriter.class,
                OfficialVerificationSnapshotCleanupRepository.class,
                OfficialVerificationSnapshotQueryService.class,
                OfficialVerificationSnapshotCommandWriters.class,
                OfficialVerificationLedgerWriters.class,
                OfficialVerificationCurrentResultCoordinator.class,
                PromptQualityMessageResolver.class);

        assertThat(method.getReturnType()).isEqualTo(OfficialVerificationOperatorSnapshotService.class);
    }

    @Test
    @DisplayName("OSS PQA should expose persisted verdict lookup without an in-memory certificate bean")
    void pqaVerdictQueryReplacesInMemoryCertificateBean() throws NoSuchMethodException {
        Method method = PqaOfficialInspectionAutoConfiguration.class.getDeclaredMethod(
                "pqaOfficialVerificationVerdictQueryService",
                OfficialVerificationExecutionLockService.class);

        assertThat(method.getReturnType()).isEqualTo(OfficialVerificationVerdictQueryService.class);
        assertThat(Arrays.stream(PqaOfficialInspectionAutoConfiguration.class.getDeclaredMethods())
                .map(Method::getName))
                .doesNotContain("pqaPromptQualityCertificateService");
    }

    @Test
    void ossCaptureFilterUsesTheSameEnablementContractAsItsService() throws NoSuchMethodException {
        Method method = PqaOfficialInspectionAutoConfiguration.class.getDeclaredMethod(
                "pqaOssOfficialSealedEvidenceCaptureFilter",
                OssOfficialSealedEvidenceCaptureService.class);

        assertThat(Arrays.stream(method.getAnnotationsByType(ConditionalOnProperty.class)))
                .anyMatch(condition ->
                        condition.prefix().equals("contexa.pqa.oss.sealed-evidence")
                                && Arrays.asList(condition.name()).contains("capture-enabled")
                                && condition.havingValue().equals("true")
                                && condition.matchIfMissing());
        assertThat(Arrays.asList(method.getAnnotation(ConditionalOnBean.class).value()))
                .contains(OssOfficialSealedEvidenceCaptureService.class);
    }

}
