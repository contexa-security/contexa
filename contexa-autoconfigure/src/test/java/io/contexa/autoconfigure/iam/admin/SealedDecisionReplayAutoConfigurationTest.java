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
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.inspection.PromptInspectionScheduler;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import io.contexa.contexaiam.admin.promptquality.inspection.SealedDecisionReplayApiController;
import io.contexa.contexaiam.admin.promptquality.inspection.SealedDecisionReplays;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsole;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionTrials;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.support.StaticMessageSource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * The replay of sealed decisions is wired wherever the sealed packages are kept, apart from the prompt inspection:
 * switching the inspection off leaves the replay, its API and the prompt version trials that stand on it. Enterprise
 * keeps sealed packages in its own schema, so the replay is off while Enterprise is enabled.
 */
class SealedDecisionReplayAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PromptInspectionAutoConfiguration.class,
                    SealedDecisionReplayAutoConfiguration.class, PromptVersionConsoleAutoConfiguration.class))
            .withBean("contexaObjectMapper", ObjectMapper.class, ObjectMapper::new)
            .withBean(SealedEvidencePackageRepository.class, () -> mock(SealedEvidencePackageRepository.class))
            .withBean("contexaJdbcTemplate", JdbcTemplate.class, () -> mock(JdbcTemplate.class))
            .withBean("contexaTransactionManager", PlatformTransactionManager.class,
                    () -> mock(PlatformTransactionManager.class))
            .withBean("messageSource", StaticMessageSource.class, StaticMessageSource::new)
            .withBean(PromptVersionService.class, () -> mock(PromptVersionService.class));

    @Test
    void theReplayItsApiAndTheTrialsAreWiredBesideTheInspection() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(PromptInspector.class);
            assertThat(context).hasSingleBean(SealedDecisionReplays.class);
            assertThat(context).hasSingleBean(SealedDecisionReplayApiController.class);
            // docs/agent OC-5: the operator's replay API, which says it is unavailable without the pipeline.
            assertThat(context.getBean(SealedDecisionReplayApiController.class).bundles()).isNotEmpty();
            assertThat(context).hasSingleBean(PromptVersionTrials.class);
        });
    }

    /** K154: the inspection's switch turns off the inspection alone. */
    @Test
    void withTheInspectionSwitchedOffTheReplayAndTheTrialsStay() {
        runner.withPropertyValues("contexa.prompt-inspection.enabled=false")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(PromptInspector.class);
                    assertThat(context).doesNotHaveBean(PromptInspectionScheduler.class);
                    assertThat(context).hasSingleBean(SealedDecisionReplays.class);
                    assertThat(context).hasSingleBean(SealedDecisionReplayApiController.class);
                    assertThat(context.getBean(SealedDecisionReplayApiController.class).bundles()).isNotEmpty();
                    assertThat(context).hasSingleBean(PromptVersionTrials.class);
                    assertThat(context).hasSingleBean(PromptVersionConsole.class);
                });
    }

    @Test
    void withEnterpriseEnabledThereIsNoReplayAndSoNoTrials() {
        runner.withPropertyValues("contexa.enterprise.enabled=true")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(SealedDecisionReplays.class);
                    assertThat(context).doesNotHaveBean(SealedDecisionReplayApiController.class);
                    assertThat(context).doesNotHaveBean(PromptVersionTrials.class);
                });
    }

    @Test
    void withoutTheSealedPackageStoreThereIsNoReplay() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(SealedDecisionReplayAutoConfiguration.class))
                .withBean("contexaObjectMapper", ObjectMapper.class, ObjectMapper::new)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(SealedDecisionReplays.class);
                    assertThat(context).doesNotHaveBean(SealedDecisionReplayApiController.class);
                });
    }

    /** The replay comes after the store it reads and before the version screens whose trials ask for it. */
    @Test
    void theReplayIsRegisteredAfterTheStoreAndBeforeTheVersionScreens() throws IOException {
        assertThat(new ClassPathResource("META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports")
                .getContentAsString(StandardCharsets.UTF_8).lines().map(String::trim))
                .contains(SealedDecisionReplayAutoConfiguration.class.getName());
        assertThat(SealedDecisionReplayAutoConfiguration.class.getAnnotation(AutoConfiguration.class).after())
                .contains(SealedEvidenceStoreAutoConfiguration.class)
                .doesNotContain(PromptInspectionAutoConfiguration.class);
        assertThat(PromptVersionConsoleAutoConfiguration.class.getAnnotation(AutoConfiguration.class).after())
                .contains(SealedDecisionReplayAutoConfiguration.class);
    }
}
