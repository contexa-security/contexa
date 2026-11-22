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
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.cases.QualityCasePromotions;
import io.contexa.contexaiam.admin.promptquality.cases.QualityCaseUserDeletionListener;
import io.contexa.contexaiam.admin.promptquality.inspection.SealedDecisionReplays;
import io.contexa.contexaiam.admin.promptquality.causes.PromptQualityCauses;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityRunLine;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsole;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleController;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionTrials;
import io.contexa.contexacore.std.components.prompt.quality.QualityMeasurementState;
import io.contexa.contexacore.std.components.prompt.quality.QualityShippedMeasurements;
import io.contexa.contexaiam.admin.promptquality.measure.MeasuredQualityGateSource;
import io.contexa.contexaiam.admin.promptquality.measure.QualityAutoMeasurement;
import io.contexa.contexaiam.admin.promptquality.measure.QualityScheduledMeasurement;
import io.contexa.contexaiam.admin.promptquality.report.PromptQualityReports;
import io.contexa.contexaiam.admin.promptquality.status.PromptQualityStatus;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.support.StaticMessageSource;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Plan 6-6: the prompt version screens stand on the versions of the database: with the version service, the console
 * and its controller are registered, and the trials when the sealed decision replay is there too; without the version service, or with prompt governance off, none of them is.
 * The labelled cases of the quality measurement stand on the version service too, with the two-person confirmation
 * on unless it is turned off, and the measurements on the cases and the replay, in the line of the trials, with the
 * settings they are given.
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
                    assertThat(context).hasSingleBean(PromptQualityCases.class);
                    assertThat(context).hasSingleBean(QualityCaseUserDeletionListener.class);
                    assertThat(context.getBean(PromptQualityCases.class).twoPersonConfirmation()).isTrue();
                    assertThat(context).hasSingleBean(PromptQualityRunLine.class);
                    assertThat(context).hasSingleBean(PromptQualityMeasurements.class);
                    assertThat(context.getBean(PromptQualityMeasurements.class).settings())
                            .isEqualTo(PromptQualityMeasurements.Settings.DEFAULTS);
                    // Quality plan 3.4: the store of measurements the quality gate reads, and the measurements
                    // Contexa starts by itself once the application is ready.
                    assertThat(context).hasSingleBean(MeasuredQualityGateSource.class);
                    assertThat(context).hasSingleBean(QualityAutoMeasurement.class);
                    assertThat(context).hasBean("contexaQualityAutoMeasurementStart");
                    assertThat(context).hasSingleBean(QualityShippedMeasurements.class);
                    // Quality plan 3.5: the causes of the wrong answers.
                    assertThat(context).hasSingleBean(PromptQualityCauses.class);
                });
    }

    /**
     * Quality plan 3.6: the decisions are made cases with the store of sealed packages, and the version in use is
     * measured again on schedule, which an installation turns off with "-".
     */
    @Test
    void theOperationsOfTheQualityStandOnTheCasesTheSealsAndTheMeasurer() {
        runner.withBean(PromptVersionService.class, () -> mock(PromptVersionService.class))
                .withBean(SealedDecisionReplays.class, () -> mock(SealedDecisionReplays.class))
                .withBean(SealedEvidencePackageRepository.class, () -> mock(SealedEvidencePackageRepository.class))
                .run(context -> {
                    assertThat(context).hasSingleBean(QualityCasePromotions.class);
                    assertThat(context).hasSingleBean(QualityScheduledMeasurement.class);
                    assertThat(context.getBean(QualityScheduledMeasurement.class).nextScheduled()).isNotNull();
                    assertThat(context).hasSingleBean(PromptQualityStatus.class);
                    // Quality plan 3.7: the quality report, on the state of quality and the quality gate's source.
                    assertThat(context).hasSingleBean(PromptQualityReports.class);
                });
        runner.withBean(PromptVersionService.class, () -> mock(PromptVersionService.class))
                .withPropertyValues("contexa.pqa.oss.quality.remeasure.cron=-")
                .run(context -> {
                    assertThat(context).doesNotHaveBean(QualityCasePromotions.class);
                    assertThat(context.getBean(QualityScheduledMeasurement.class).nextScheduled()).isNull();
                });
    }

    @Test
    void theMeasurementsTakeTheirSettings() {
        runner.withBean(PromptVersionService.class, () -> mock(PromptVersionService.class))
                .withBean(SealedDecisionReplays.class, () -> mock(SealedDecisionReplays.class))
                .withPropertyValues("contexa.pqa.oss.quality.measurement.repeats=5",
                        "contexa.pqa.oss.quality.measurement.concurrency=2",
                        "contexa.pqa.oss.quality.measurement.retries=1",
                        "contexa.pqa.oss.quality.measurement.retry-delay=5s",
                        "contexa.pqa.oss.quality.measurement.call-limit=0",
                        "contexa.pqa.oss.quality.measurement.heartbeat=10s")
                .run(context -> assertThat(context.getBean(PromptQualityMeasurements.class).settings())
                        .isEqualTo(new PromptQualityMeasurements.Settings(5, 2, 1, Duration.ofSeconds(5), 0,
                                Duration.ofSeconds(10))));
    }

    @Test
    void theTwoPersonConfirmationOfTheCasesCanBeTurnedOff() {
        runner.withBean(PromptVersionService.class, () -> mock(PromptVersionService.class))
                .withPropertyValues("contexa.pqa.oss.quality.two-person-confirmation=false")
                .run(context -> assertThat(context.getBean(PromptQualityCases.class).twoPersonConfirmation())
                        .isFalse());
    }

    @Test
    void withoutTheSealedDecisionReplayThereAreNoTrials() {
        runner.withBean(PromptVersionService.class, () -> mock(PromptVersionService.class))
                .run(context -> {
                    assertThat(context).hasSingleBean(PromptVersionConsole.class);
                    assertThat(context).doesNotHaveBean(PromptVersionTrials.class);
                    assertThat(context).doesNotHaveBean(PromptQualityMeasurements.class);
                    assertThat(context).hasSingleBean(PromptQualityCases.class);
                    // The decisions rated inadequate are put down to their causes without the replay too.
                    assertThat(context).hasSingleBean(PromptQualityCauses.class);
                    // Quality plan 3.4: without the replay nothing can be measured, which the gate warns of only.
                    assertThat(context.getBean(MeasuredQualityGateSource.class)
                            .read("PLATFORM_GLOBAL", "cortex.security-decision", "v2.0", "v1.0"))
                            .satisfies(reading -> {
                                assertThat(reading.state()).isEqualTo(QualityMeasurementState.UNMEASURABLE);
                                assertThat(reading.detail())
                                        .isEqualTo(MeasuredQualityGateSource.NO_MEASUREMENT_RUNNER);
                            });
                });
    }

    @Test
    void withoutTheVersionServiceOrWithGovernanceOffThereAreNoScreens() {
        runner.run(context -> {
            assertThat(context).doesNotHaveBean(PromptVersionConsole.class);
            assertThat(context).doesNotHaveBean(PromptVersionConsoleController.class);
            assertThat(context).doesNotHaveBean(PromptQualityCases.class);
            assertThat(context).doesNotHaveBean(PromptQualityCauses.class);
        });
        runner.withBean(PromptVersionService.class, () -> mock(PromptVersionService.class))
                .withPropertyValues("contexa.prompt.governance.enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(PromptVersionConsole.class));
    }
}
