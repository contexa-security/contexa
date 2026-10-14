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

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.Executor;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R1b-6: a period is inspected again by the automatic round, so the re-inspection keeps no job list in memory and runs
 * on no executor of its own (an executor that refused a job left it running forever).
 */
class PromptInspectionReinspectionShapeTest {

    @Test
    void theReinspectionKeepsNoJobListAndRunsOnNoExecutorOfItsOwn() {
        assertThat(Arrays.stream(PromptInspectionReinspection.class.getDeclaredFields()).map(Field::getType))
                .doesNotContain(Executor.class, Map.class);
        assertThat(Arrays.stream(PromptInspectionReinspection.class.getMethods()).map(Method::getName))
                .doesNotContain("jobs", "progress", "start");
        assertThat(Arrays.stream(PromptInspectionReinspection.class.getDeclaredClasses()).map(Class::getSimpleName))
                .doesNotContain("Job", "State", "Progress");
    }
}
