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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.repository.prompt.PromptGovernanceBudgetProfileRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceChangeRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceEvaluationRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceModelCompatibilityRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRegistryRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseApprovalRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseWorkflowRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRollbackRecordRepository;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionStore;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.version.AuditLogPromptVersionAudit;
import io.contexa.contexaiam.admin.promptquality.version.JdbcPromptVersionStore;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionAudit;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionFolderScanner;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionResolver;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Plan 6-3: the versions of the database are wired in every installation with the console's database: the version
 * service, the store the engine reads (the database before the product documents), the resolver as the decision's
 * selector whatever {@code prompt-bundle.selector} says, the audit log and the start of a node after the registry's;
 * the document folder only with {@code contexa.prompt.versions.directory}. Without the console's database none is.
 */
class PromptVersionAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PromptVersionAutoConfiguration.class))
            .withBean("contexaJdbcTemplate", JdbcTemplate.class, () -> mock(JdbcTemplate.class))
            .withBean("contexaObjectMapper", ObjectMapper.class, ObjectMapper::new);

    /** With the prompt governance: its registry and its repositories, as {@link PromptGovernanceAutoConfigurationTest}. */
    private final ApplicationContextRunner withGovernance = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PromptVersionAutoConfiguration.class,
                    PromptGovernanceAutoConfiguration.class))
            .withBean("contexaJdbcTemplate", JdbcTemplate.class, () -> mock(JdbcTemplate.class))
            .withBean("contexaObjectMapper", ObjectMapper.class, ObjectMapper::new)
            .withBean(PromptQualityMessageResolver.class, () -> mock(PromptQualityMessageResolver.class))
            .withBean(PromptGovernanceRegistryRepository.class, () -> mock(PromptGovernanceRegistryRepository.class))
            .withBean(PromptGovernanceChangeRecordRepository.class, () -> mock(PromptGovernanceChangeRecordRepository.class))
            .withBean(PromptGovernanceEvaluationRecordRepository.class,
                    () -> mock(PromptGovernanceEvaluationRecordRepository.class))
            .withBean(PromptGovernanceReleaseApprovalRepository.class,
                    () -> mock(PromptGovernanceReleaseApprovalRepository.class))
            .withBean(PromptGovernanceReleaseWorkflowRepository.class,
                    () -> mock(PromptGovernanceReleaseWorkflowRepository.class))
            .withBean(PromptGovernanceRollbackRecordRepository.class,
                    () -> mock(PromptGovernanceRollbackRecordRepository.class))
            .withBean(PromptGovernanceModelCompatibilityRepository.class,
                    () -> mock(PromptGovernanceModelCompatibilityRepository.class))
            .withBean(PromptGovernanceBudgetProfileRepository.class,
                    () -> mock(PromptGovernanceBudgetProfileRepository.class));

    @Test
    void theVersionsAreWiredAndTheFolderIsNotReadWithoutItsSetting() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(PromptVersionService.class);
            assertThat(context.getBean(PromptVersionStore.class)).isInstanceOf(JdbcPromptVersionStore.class);
            assertThat(context.getBean(PromptBundleSelector.class)).isInstanceOf(PromptVersionResolver.class);
            // Without the audit facade nothing records; the runner still starts the versions.
            assertThat(context.getBean(PromptVersionAudit.class)).isNotInstanceOf(AuditLogPromptVersionAudit.class);
            assertThat(context.getBean("contexaPromptVersionStartupRunner")).isInstanceOf(ApplicationRunner.class);
            assertThat(context).doesNotHaveBean(PromptVersionFolderScanner.class);
        });
    }

    @Test
    void theFolderIsReadWhenTheSettingNamesOneAndTheAuditLogRecordsWithTheFacade() {
        runner.withPropertyValues("contexa.prompt.versions.directory=/srv/contexa/prompt-versions")
                .withBean(CentralAuditFacade.class, () -> mock(CentralAuditFacade.class))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(PromptVersionFolderScanner.class);
                    assertThat(context.getBean(PromptVersionAudit.class)).isInstanceOf(AuditLogPromptVersionAudit.class);
                });
    }

    @Test
    void withoutTheConsolesDatabaseNothingIsWired() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(PromptVersionAutoConfiguration.class))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(PromptVersionService.class);
                    assertThat(context).doesNotHaveBean(PromptBundleSelector.class);
                    assertThat(context).doesNotHaveBean(PromptVersionStore.class);
                });
    }

    /**
     * The resolver is the decision's selector whatever {@code prompt-bundle.selector} says, the registry's selector
     * standing aside; with prompt governance turned off it is still, without the registry.
     */
    @Test
    void theResolverIsTheOneSelectorWithOrWithoutTheRegistry() {
        for (String selector : List.of("registry", "configuration")) {
            withGovernance.withPropertyValues("contexa.security.tiered.prompt-bundle.selector=" + selector)
                    .run(context -> {
                        assertThat(context).hasNotFailed();
                        assertThat(context).hasSingleBean(PromptBundleSelector.class);
                        assertThat(context.getBean(PromptBundleSelector.class)).as(selector)
                                .isInstanceOf(PromptVersionResolver.class);
                        assertThat(context).doesNotHaveBean("contexaPromptBundleSelector");
                    });
        }
        withGovernance.withPropertyValues("contexa.prompt.governance.enabled=false").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(PromptBundleSelector.class)).isInstanceOf(PromptVersionResolver.class);
            assertThat(context).doesNotHaveBean("contexaPromptGovernanceRegistryBootstrapRunner");
        });
    }

    /** The registry's start registers the bundle row the start of the versions retires, so it runs first. */
    @Test
    void theStartOfTheVersionsRunsAfterTheRegistrysStart() {
        withGovernance.run(context -> {
            Map<ApplicationRunner, String> names = new IdentityHashMap<>();
            context.getBeansOfType(ApplicationRunner.class).forEach((name, runner) -> names.put(runner, name));
            List<String> runners = context.getBeanProvider(ApplicationRunner.class).orderedStream().map(names::get)
                    .toList();
            assertThat(runners).containsSubsequence("contexaPromptGovernanceRegistryBootstrapRunner",
                    "contexaPromptVersionStartupRunner");
        });
    }
}
