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
package io.contexa.contexacore.std.components.prompt.bundle;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ConfiguredPromptBundleSelectorTest {

    @Test
    void aConfiguredBundleIsChosenByTheConfiguration() {
        PromptBundleSelection selection = new ConfiguredPromptBundleSelector(" 2026.10.12-v20 ").select(null, "alice");

        assertThat(selection.bundleVersion()).isEqualTo("2026.10.12-v20");
        assertThat(selection.source()).isEqualTo(PromptBundleSelectionSource.CONFIGURATION);
    }

    @Test
    void noConfiguredBundleLeavesTheChoiceToTheBuildDefault() {
        for (String active : new String[]{null, "", "  "}) {
            PromptBundleSelection selection = new ConfiguredPromptBundleSelector(active).select(null, "alice");

            assertThat(selection).isEqualTo(PromptBundleSelection.none());
            assertThat(selection.bundleVersion()).isNull();
            assertThat(selection.source()).isEqualTo(PromptBundleSelectionSource.BUILD_DEFAULT);
        }
    }
}
