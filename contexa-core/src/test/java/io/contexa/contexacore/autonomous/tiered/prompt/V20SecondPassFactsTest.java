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
package io.contexa.contexacore.autonomous.tiered.prompt;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 판정층 8절 7 (docs/showcase/판정층-수정계획.md): E-4 made the second pass ask its model in every bundle, so a v20
 * second pass, too, states only what it knows that the first did not. The v20 dictionary has no line for "none new"
 * and stays as v20.25 was frozen: after a first pass that retrieved its own past records the v20 second pass asks
 * with the first prompt alone, with no SECOND PASS block; after one that could not retrieve any it gets what the
 * second pass found, as before.
 */
class V20SecondPassFactsTest {

    private static SecurityDecisionGoldenRender golden;
    private static JsonNode a3;
    private static TieredStrategyProperties v20;
    private static String first;

    @BeforeAll
    static void render() {
        golden = SecurityDecisionGoldenRender.load();
        v20 = new TieredStrategyProperties();
        v20.getPromptBundle().setActive(SecurityDecisionPromptBundles.V20.version());
        a3 = golden.cases().stream().filter(item -> "A3".equals(item.path("caseKey").asText())).findFirst()
                .orElseThrow();
        first = golden.render(a3, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, v20).userText();
    }

    /** The user prompt of A3's second pass after a first pass whose past record search ended in the state. */
    private static String secondPassPrompt(String firstPassState) {
        return golden.render(a3, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, v20, null,
                Map.of("layer2FirstPassUserPrompt", first, "layer2FirstPassVerdict", "ESCALATE",
                        "layer2FirstPassPastRecordsState", firstPassState)).userText();
    }

    /** The SECOND PASS block of A3's second pass after a first pass whose past record search ended in the state. */
    private static String secondPassBlock(String firstPassState) {
        String text = secondPassPrompt(firstPassState);
        int start = text.indexOf("=== SECOND PASS");
        assertThat(start).as("the second pass block is drawn").isGreaterThan(0);
        return text.substring(start);
    }

    @ParameterizedTest
    @ValueSource(strings = {"AVAILABLE", "ZERO_RESULTS"})
    void aFirstPassThatRetrievedItsRecordsIsAskedAgainWithTheFirstPromptAlone(String state) {
        String prompt = secondPassPrompt(state);

        assertThat(prompt).isEqualTo(first.stripTrailing())
                .doesNotContain("=== SECOND PASS")
                .doesNotContain("not retrieved");
    }

    @Test
    void aFirstPassThatCouldNotRetrieveGetsWhatTheSecondPassFound() {
        String block = secondPassBlock("TIMEOUT");

        assertThat(block).contains("PastRecord{i}: 5 found (first pass: not retrieved, TIMEOUT)")
                .contains("NewPastRecord1");
    }
}
