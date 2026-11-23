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
package io.contexa.contexacore.monitoring.ai;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Quality plan 3.6: the signs that an allowed decision may be a miss, one at a time and over its record's columns. */
class DecisionRiskSignalsTest {

    @Test
    void eachSignIsReadFromItsOwnValueAndOnlyOfAnAllowedDecision() {
        assertThat(DecisionRiskSignals.of("ALLOW", "H1", false, false, 2, "ESTABLISHED", 3)).isEmpty();
        assertThat(DecisionRiskSignals.of("ALLOW", "h3", false, false, null, null, 3))
                .containsExactly(DecisionRiskSignals.Signal.NOT_LEGITIMATE_WORK);
        assertThat(DecisionRiskSignals.of("allow", " ", true, false, null, null, 3))
                .containsExactly(DecisionRiskSignals.Signal.SECOND_ANALYSIS);
        assertThat(DecisionRiskSignals.of("ALLOW", null, false, true, null, null, 3))
                .containsExactly(DecisionRiskSignals.Signal.ASKED_AGAIN);
        assertThat(DecisionRiskSignals.of("ALLOW", null, false, false, 3, null, 3))
                .containsExactly(DecisionRiskSignals.Signal.MANY_UNKNOWN_FACTS);
        assertThat(DecisionRiskSignals.of("ALLOW", null, false, false, 0, null, 0))
                .as("a threshold below one reads as one").isEmpty();
        assertThat(DecisionRiskSignals.of("ALLOW", null, false, false, null, "PROVISIONAL", 3))
                .containsExactly(DecisionRiskSignals.Signal.IMMATURE_BASELINE);
        assertThat(DecisionRiskSignals.of("BLOCK", "H3", true, true, 9, "NONE", 3)).isEmpty();
        assertThat(DecisionRiskSignals.of(null, "H3", true, true, 9, "NONE", 3)).isEmpty();
    }

    @Test
    void theSecondAnalysisAndAskingAgainAreReadAsTheConsoleReadsThem() {
        assertThat(DecisionRiskSignals.secondAnalysis("2")).isTrue();
        assertThat(DecisionRiskSignals.secondAnalysis("1")).isFalse();
        assertThat(DecisionRiskSignals.secondAnalysis(null)).isFalse();
        assertThat(DecisionRiskSignals.askedAgain(1, "LAYER1")).isFalse();
        assertThat(DecisionRiskSignals.askedAgain(2, "LAYER1")).isTrue();
        assertThat(DecisionRiskSignals.askedAgain(2, "LAYER2")).isFalse();
        assertThat(DecisionRiskSignals.askedAgain(3, "LAYER2")).isTrue();
        assertThat(DecisionRiskSignals.askedAgain(2, null)).isTrue();
        assertThat(DecisionRiskSignals.askedAgain(null, "LAYER2")).isFalse();
    }

    @Test
    void theSqlNamesTheColumnsOfTheAliasAndWritesTheThresholdAsANumber() {
        String condition = DecisionRiskSignals.sqlCondition("d", 4);
        assertThat(condition).startsWith("(d.final_action = 'ALLOW' AND (").contains("d.unknown_fact_count >= 4")
                .contains("d.most_likely_hypothesis").contains("d.analysis_depth").contains("d.model_call_count")
                .contains("d.decision_stage").contains("d.baseline_status").doesNotContain("o.");
        assertThat(DecisionRiskSignals.sqlCount("d", 0)).contains("d.unknown_fact_count >= 1");
    }
}
