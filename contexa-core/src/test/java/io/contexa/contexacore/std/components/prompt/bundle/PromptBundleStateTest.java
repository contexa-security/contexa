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

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import io.contexa.contexacore.std.components.prompt.PromptReleaseStatus;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PromptBundleStateTest {

    @Test
    void everyValueOfTheThreeOlderVocabulariesReadsAsOneCanonicalState() {
        for (PromptReleaseStatus status : PromptReleaseStatus.values()) {
            assertThat(PromptBundleState.fromStoredValue(status.name())).as(status.name()).isPresent();
        }
        for (LearningArtifactReleaseState state : LearningArtifactReleaseState.values()) {
            assertThat(PromptBundleState.fromStoredValue(state.name())).as(state.name()).isPresent();
        }
        Map<String, PromptBundleState> registryStrings = Map.of(
                "ACTIVE_FOR_SCOPE", PromptBundleState.CANARY,
                "PRODUCTION", PromptBundleState.ACTIVE,
                "ACTIVE", PromptBundleState.ACTIVE,
                "RELEASED", PromptBundleState.ACTIVE,
                "CURRENT", PromptBundleState.ACTIVE,
                "RUNTIME_APPROVED", PromptBundleState.ACTIVE,
                "PRODUCTION_APPROVED", PromptBundleState.ACTIVE,
                "DRAFT", PromptBundleState.AVAILABLE);
        registryStrings.forEach((value, state) ->
                assertThat(PromptBundleState.fromStoredValue(value)).as(value).contains(state));
    }

    @Test
    void theFormerTransitionOrderMapsOneToOne() {
        assertThat(PromptBundleState.fromReleaseStatus(PromptReleaseStatus.DRAFT)).isEqualTo(PromptBundleState.AVAILABLE);
        assertThat(PromptBundleState.fromReleaseStatus(PromptReleaseStatus.EVAL_ONLY)).isEqualTo(PromptBundleState.SHADOW);
        assertThat(PromptBundleState.fromReleaseStatus(PromptReleaseStatus.CANARY)).isEqualTo(PromptBundleState.CANARY);
        assertThat(PromptBundleState.fromReleaseStatus(PromptReleaseStatus.PRODUCTION)).isEqualTo(PromptBundleState.ACTIVE);
        assertThat(PromptBundleState.fromReleaseStatus(PromptReleaseStatus.ROLLED_BACK)).isEqualTo(PromptBundleState.DEPRECATED);
        assertThat(PromptBundleState.fromReleaseStatus(PromptReleaseStatus.RETIRED)).isEqualTo(PromptBundleState.RETIRED);
        for (PromptBundleState state : PromptBundleState.values()) {
            assertThat(PromptBundleState.fromReleaseStatus(state.releaseStatus())).isEqualTo(state);
        }
    }

    @Test
    void storedValuesAreReadWithoutCaseOrSurroundingSpaceAndUnknownValuesHaveNoState() {
        assertThat(PromptBundleState.fromStoredValue(" active_for_scope ")).contains(PromptBundleState.CANARY);
        assertThat(PromptBundleState.fromStoredValue("SOMETHING_ELSE")).isEmpty();
        assertThat(PromptBundleState.fromStoredValue(null)).isEmpty();
        assertThat(PromptBundleState.isExecuting("SOMETHING_ELSE")).isFalse();
        assertThat(PromptBundleState.canonicalName("PRODUCTION")).isEqualTo("ACTIVE");
        assertThat(PromptBundleState.canonicalName("SOMETHING_ELSE")).isEqualTo("SOMETHING_ELSE");
    }

    @Test
    void onlyDefaultAndScopedEnforcementAreExecuting() {
        assertThat(PromptBundleState.ACTIVE.executing()).isTrue();
        assertThat(PromptBundleState.CANARY.executing()).isTrue();
        assertThat(PromptBundleState.AVAILABLE.executing()).isFalse();
        assertThat(PromptBundleState.SHADOW.executing()).isFalse();
        assertThat(PromptBundleState.DEPRECATED.executing()).isFalse();
        assertThat(PromptBundleState.RETIRED.executing()).isFalse();
    }

    @Test
    void theSqlListOfStatesCarriesEveryNameThatReadsAsThem() {
        String executing = PromptBundleState.sqlList(PromptBundleState.CANARY, PromptBundleState.ACTIVE);

        assertThat(executing).contains("'CANARY'", "'ACTIVE_FOR_SCOPE'", "'CANARY_READY'", "'ACTIVE'", "'PRODUCTION'",
                "'PROMOTED'", "'RELEASED'", "'CURRENT'", "'RUNTIME_APPROVED'", "'PRODUCTION_APPROVED'");
        assertThat(executing).doesNotContain("'DRAFT'", "'EVAL_ONLY'", "'ROLLED_BACK'", "'RETIRED'");
    }
}
