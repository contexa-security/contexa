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
import io.contexa.contexaiam.admin.promptquality.inspection.SealedDecisionReplays;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsole;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleController;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionTrials;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.support.StaticMessageSource;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Plan 6-6: the prompt version screens stand on the versions of the database: with the version service, the console
 * and its controller are registered, and the trials when the sealed decision replay is there too; without the version service, or with prompt governance off, none of them is.
 */
class PromptVersionConsoleAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PromptVersionConsoleAutoConfiguration.class))
            .withBean("contexaJdbcTemplate", JdbcTemplate.class, () -> mock(JdbcTemplate.class))
            .withBean("contexaObjectMapper", ObjectMapper.class, ObjectMapper::new)
            .withBean("messageSource", StaticMessageSource.class, StaticMessageSource::new);

    @Test
    void theScreensStandOnTheVersionService() {
        runner.withBean(PromptVersionService.class, () -> mock(PromptVersionService.class))
                .withBean(SealedDecisionReplays.class, () -> mock(SealedDecisionReplays.class))
                .run(context -> {
                    assertThat(context).hasSingleBean(PromptVersionConsole.class);
                    assertThat(context).hasSingleBean(PromptVersionConsoleController.class);
                    assertThat(context).hasSingleBean(PromptVersionTrials.class);
                });
    }

    @Test
    void withoutTheSealedDecisionReplayThereAreNoTrials() {
        runner.withBean(PromptVersionService.class, () -> mock(PromptVersionService.class))
                .run(context -> {
                    assertThat(context).hasSingleBean(PromptVersionConsole.class);
                    assertThat(context).doesNotHaveBean(PromptVersionTrials.class);
                });
    }

    @Test
    void withoutTheVersionServiceOrWithGovernanceOffThereAreNoScreens() {
        runner.run(context -> {
            assertThat(context).doesNotHaveBean(PromptVersionConsole.class);
            assertThat(context).doesNotHaveBean(PromptVersionConsoleController.class);
        });
        runner.withBean(PromptVersionService.class, () -> mock(PromptVersionService.class))
                .withPropertyValues("contexa.prompt.governance.enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(PromptVersionConsole.class));
    }
}
