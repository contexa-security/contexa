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

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.decision.MinimumActionRules;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.llm.client.StructuredOutputMode;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W4-4 (dictionary 6): the v20 system text states the minimum action rules the host turned on, with the values the host
 * set, and nothing about them when none is on; a changed setting is not served from the cached system text.
 */
class MinimumActionRulesSystemTextTest {

    @Test
    void theSystemTextStatesTheRulesTheHostTurnedOnWithItsValues() {
        SecurityDecisionPromptSections sections = sections();
        sections.setMinimumActionSettings(new MinimumActionRules.Settings(true, 3, "CRITICAL", false, true, "CHALLENGE"));

        assertThat(sections.buildSystemInstructionV20())
                .contains("P1 MIN_P1_IDENTITY_DEVIATION: ResourceClass is CRITICAL and DeviationsFromBaseline names at"
                                + " least 3 of time, day, network and device as unexplained.",
                        "P3 MIN_P3_POLICY_NOT_SATISFIED: PolicySatisfied is no. Floor: CHALLENGE.")
                .doesNotContain("MIN_P2");

        sections.setMinimumActionSettings(new MinimumActionRules.Settings(false, 2, "SENSITIVE", false, false, "CHALLENGE"));

        assertThat(sections.buildSystemInstructionV20()).doesNotContainIgnoringCase("minimum action rule")
                .doesNotContain("MIN_P")
                .contains("Use only the facts the user prompt states. Make one holistic judgment:");
    }

    /** Q-87 (N-P3-1): every rule names its floor; P3's is a review, with the reason a verification does not do. */
    @Test
    void everyRuleNamesItsFloor() {
        SecurityDecisionPromptSections sections = sections();

        assertThat(sections.buildSystemInstructionV20())
                .contains("as unexplained. Floor: CHALLENGE.",
                        "P3 MIN_P3_POLICY_NOT_SATISFIED: PolicySatisfied is no. Floor: ESCALATE (a verified user does not"
                                + " supply the missing record).",
                        "from the weakest: ALLOW, CHALLENGE, ESCALATE, BLOCK");
    }

    @Test
    void aChangedSettingIsNotServedFromTheCachedSystemText() {
        SecurityDecisionPromptSections sections = sections();
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(sections);
        String before = template.generateSystemPrompt(request(), null);

        sections.setMinimumActionSettings(new MinimumActionRules.Settings(true, 2, "SENSITIVE", true, false, "CHALLENGE"));

        String after = template.generateSystemPrompt(request(), null);
        assertThat(before).contains("P3 MIN_P3_POLICY_NOT_SATISFIED");
        assertThat(after).doesNotContain("P3 MIN_P3_POLICY_NOT_SATISFIED").contains("P1 MIN_P1_IDENTITY_DEVIATION");
    }

    private static SecurityDecisionPromptSections sections() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V20.version());
        return new SecurityDecisionPromptSections(new SecurityEventEnricher(), properties, event -> Optional.empty(),
                new PromptContextComposer(), null, null, null);
    }

    private static SecurityDecisionRequest request() {
        SecurityEvent event = SecurityEvent.builder().eventId("event-w44-rules").metadata(new LinkedHashMap<>()).build();
        SecurityDecisionRequest request = new SecurityDecisionRequest(new SecurityDecisionContext(event,
                new SecurityDecisionStandardPromptTemplate.SessionContext(), null, List.of()));
        request.withParameter("promptBudgetProfile", PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT.profileKey());
        request.withParameter("structuredOutputMode", StructuredOutputMode.VALIDATED_CONVERTER.name());
        return request;
    }
}
