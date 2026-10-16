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
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * N-GOLD-1: the golden render draws the baseline the sealed prompts state. Each case is rendered with the v20 bundle
 * the sealed prompts were drawn with and the budget profile its source decision was sealed with; its baseline status
 * line and its line of deviations from the baseline are the sealed prompt's (26 cases).
 */
class SecurityDecisionGoldenRenderBaselineTest {

    private static final List<String> NAMES = List.of("BaselineStatus", "DeviationsFromBaseline");

    @Test
    void theBaselineStatusAndTheDeviationsAreTheSealedOnes() {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V20.version());
        List<String> differing = new ArrayList<>();
        for (JsonNode goldenCase : golden.cases()) {
            PromptBudgetProfile profile = PromptBudgetProfile.fromKey(goldenCase.path("budgetProfile").asText(),
                    PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT);
            String rendered = golden.render(goldenCase, profile, properties).userText();
            String sealed = goldenCase.path("rawUserPrompt").asText();
            for (String name : NAMES) {
                String expected = line(sealed, name);
                String actual = line(rendered, name);
                if (!Objects.equals(expected, actual)) {
                    differing.add(goldenCase.path("caseKey").asText() + " " + name + "\n  sealed   " + expected
                            + "\n  rendered " + actual);
                }
            }
        }
        assertThat(golden.cases()).hasSize(26);
        assertThat(differing).isEmpty();
    }

    /** The line of the named entry, with its fact ID when it has one; null when the prompt draws no such line. */
    private static String line(String prompt, String name) {
        Pattern entry = Pattern.compile("^(\\[[A-Z][0-9]{1,2}] )?" + name + ": ");
        for (String line : prompt.split("\n")) {
            if (entry.matcher(line).find()) {
                return line;
            }
        }
        return null;
    }
}
