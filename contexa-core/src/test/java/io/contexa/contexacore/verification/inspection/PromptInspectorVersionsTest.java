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

import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

/** R1b-7: every raise of the inspector version is kept once, in order, with its reason, and the last is the one run. */
class PromptInspectorVersionsTest {

    @Test
    void everyRaiseIsKeptOnceInOrderWithItsReason() {
        assertThat(PromptInspectorVersions.ALL).extracting(PromptInspectorVersions.Version::number)
                .containsExactlyElementsOf(IntStream.rangeClosed(1, PromptInspectorVersions.ALL.size()).boxed().toList());
        assertThat(PromptInspectorVersions.ALL).hasSizeGreaterThanOrEqualTo(12)
                .allSatisfy(version -> assertThat(version.reason()).isNotBlank());
        assertThat(PromptInspectorVersions.ALL.get(4).reason()).contains("P3 extra 12");
    }

    @Test
    void theInspectorRunsTheLastVersion() {
        assertThat(PromptInspector.INSPECTOR_VERSION).isEqualTo(PromptInspectorVersions.current().name());
        assertThat(PromptInspectorVersions.current().number()).isEqualTo(PromptInspectorVersions.ALL.size());
    }
}
