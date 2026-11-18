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
 * W4-4 (dictionary 6), K32: when the host enforces the minimum action rules, the system text states the rules the host
 * turned on, with the values the host set, and nothing about them when none is on or when the host only observes them;
 * a changed setting is not served from the cached system text. Plan 6-2: the v20 system text said this before; the
 * product document's minimum action part says it now.
 */
class MinimumActionRulesSystemTextTest {

    @Test
    void theSystemTextStatesTheRulesTheHostTurnedOnWithItsValues() {
        SecurityDecisionPromptSections sections = sections();
        sections.setMinimumActionSettings(new MinimumActionRules.Settings(true, 3, "CRITICAL", false, true, "CHALLENGE"),
                "ENFORCE");

        assertThat(sections.buildSystemInstructionV1(contextOf()))
                .contains("P1: ResourceClass is CRITICAL,", "in at least 3 of time, day, network and device",
                        "P3: the company policy", "Floor: CHALLENGE.")
                .doesNotContain("P2:");

        sections.setMinimumActionSettings(new MinimumActionRules.Settings(false, 2, "SENSITIVE", false, false, "CHALLENGE"),
                "ENFORCE");

        assertThat(sections.buildSystemInstructionV1(contextOf())).doesNotContain("Minimum action rules")
                .doesNotContain("P1:").doesNotContain("P3:");
    }

    /** K32: the host only observing the rules, the system text says nothing about them. */
    @Test
    void anObservedRuleIsNotStated() {
        SecurityDecisionPromptSections sections = sections();
        sections.setMinimumActionSettings(MinimumActionRules.Settings.DEFAULTS, "OBSERVE");

        assertThat(sections.buildSystemInstructionV1(contextOf())).doesNotContain("Minimum action rules");
    }

    /** Q-87 (N-P3-1): every rule names its floor; P3's is a review, with the reason a verification does not do. */
    @Test
    void everyRuleNamesItsFloor() {
        SecurityDecisionPromptSections sections = sections();
        sections.setMinimumActionSettings(MinimumActionRules.Settings.DEFAULTS, "ENFORCE");

        assertThat(sections.buildSystemInstructionV1(contextOf()))
                .contains("Floor: CHALLENGE.", "Floor: ESCALATE (a verified user does not supply the missing record).",
                        "A later check raises a response weaker than the floor of a rule that applies to that floor.");
    }

    @Test
    void aChangedSettingIsNotServedFromTheCachedSystemText() {
        SecurityDecisionPromptSections sections = sections();
        sections.setMinimumActionSettings(MinimumActionRules.Settings.DEFAULTS, "ENFORCE");
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(sections);
        String before = template.generateSystemPrompt(request(), null);

        sections.setMinimumActionSettings(new MinimumActionRules.Settings(true, 2, "SENSITIVE", true, false, "CHALLENGE"),
                "ENFORCE");

        String after = template.generateSystemPrompt(request(), null);
        assertThat(before).contains("P3: the company policy");
        assertThat(after).doesNotContain("P3: the company policy").contains("P1: ResourceClass is");
    }

    private static SecurityDecisionPromptSections sections() {
        return new SecurityDecisionPromptSections(new SecurityEventEnricher(), new TieredStrategyProperties(),
                event -> Optional.empty(), new PromptContextComposer(), null, null, null);
    }

    private static SecurityPromptBuildContext contextOf() {
        SecurityEvent event = SecurityEvent.builder().eventId("event-w44-floors").metadata(new LinkedHashMap<>()).build();
        return new SecurityPromptBuildContext(event, null, null, List.of(), null, null, null, null, null, null, null);
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
