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
package io.contexa.contexacore.verification.inspection;

import org.junit.jupiter.api.Test;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The automatic round's schedule: its interval and first delay default to the scheduler's own constants, which the
 * settings class starts from too (R1b-3), and the design values are thirty seconds each.
 */
class PromptInspectionSchedulerTest {

    @Test
    void theScheduleReadsItsDefaultsFromTheSchedulersConstants() throws NoSuchMethodException {
        Scheduled scheduled = PromptInspectionScheduler.class.getMethod("inspectUninspected").getAnnotation(Scheduled.class);

        assertThat(scheduled.fixedDelayString())
                .isEqualTo("${contexa.prompt-inspection.interval:" + PromptInspectionScheduler.DEFAULT_INTERVAL + "}");
        assertThat(scheduled.initialDelayString())
                .isEqualTo("${contexa.prompt-inspection.initial-delay:" + PromptInspectionScheduler.DEFAULT_INITIAL_DELAY + "}");
    }

    @Test
    void theRoundRunsEveryThirtySecondsAfterAFirstDelayOfThirtySeconds() {
        assertThat(Duration.parse(PromptInspectionScheduler.DEFAULT_INTERVAL)).isEqualTo(Duration.ofSeconds(30));
        assertThat(Duration.parse(PromptInspectionScheduler.DEFAULT_INITIAL_DELAY)).isEqualTo(Duration.ofSeconds(30));
    }
}
