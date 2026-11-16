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

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
import io.contexa.contexacore.autonomous.context.decision.DecisionFactsResolver;
import io.contexa.contexacore.autonomous.context.decision.MinimumActionRules;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionRawOutputContractInspector;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionV1OutputInspector;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionV21OutputInspector;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * v1.0 (plan 2.2 B6, 2.3.2 B4-B6, A16): the v1.0 response check reads the conclusions the context kept beside its
 * records; it checks the decision rules' boundaries only in the fallback variants, the minimum action floors when the
 * host enforces them, and a reason that rests on past records the prompt does not draw.
 */
class SecurityDecisionV1ResponseCheckTest {

    private final SecurityDecisionV1OutputInspector inspector = new SecurityDecisionV1OutputInspector();

    @Test
    void aV1RenderKeepsTheConclusionsBesideTheRecordsItsPromptStates() {
        CanonicalSecurityContext used = render().used();

        assertThat(used.getConclusionFacts()).isNotNull();
        assertThat(used.getConclusionFacts().fact(DecisionFactsResolver.POLICY_SATISFIED)).isPresent();
        assertThat(used.getDecisionFacts().fact(DecisionFactsResolver.POLICY_SATISFIED)).isEmpty();
    }

    @Test
    void theFallbackVariantsCheckTheBoundariesOnTheConclusions() {
        InspectionGolden.Render render = render();
        DecisionFacts conclusions = render.used().getConclusionFacts();

        SecurityDecisionV1OutputInspector.V1Inspection block = inspect(render, "BLOCK",
                new SecurityDecisionV1OutputInspector.V1Rules(conclusions, true, null, true));
        SecurityDecisionV1OutputInspector.V1Inspection challenge = inspect(render, "CHALLENGE",
                new SecurityDecisionV1OutputInspector.V1Rules(conclusions, true, null, true));

        assertThat(block.ruleViolation()).isEqualTo(SecurityDecisionFactChecks.BLOCK_WITHOUT_EVIDENCE);
        assertThat(block.inspection().requiresRetry()).isTrue();
        assertThat(block.unsupportedCodesOnly()).isFalse();
        assertThat(challenge.ruleViolation()).isNull();
    }

    @Test
    void theRecordVariantsCheckTheBoundariesOnTheFactsTheirPromptsState() {
        InspectionGolden.Render render = SecurityDecisionV1BundleTest.render(MeasuredVariant.RECORD_EXACT,
                context -> {
                });
        DecisionFacts conclusions = render.used().getConclusionFacts();

        SecurityDecisionV1OutputInspector.V1Inspection block = inspect(render, "BLOCK",
                new SecurityDecisionV1OutputInspector.V1Rules(conclusions, true, null, false));

        assertThat(block.ruleViolation()).isEqualTo(SecurityDecisionFactChecks.BLOCK_WITHOUT_EVIDENCE);
        assertThat(render.userPrompt()).doesNotContain("PolicySatisfied: ");
    }

    @Test
    void anEnforcedFloorNamesTheRuleAWeakerAnswerBreaks() {
        InspectionGolden.Render render = render();
        DecisionFacts conclusions = render.used().getConclusionFacts();
        CanonicalSecurityContext.Resource resource = render.used().getResource();
        SecurityDecisionRawOutputContractInspector.MinimumActionCheck floors =
                new SecurityDecisionRawOutputContractInspector.MinimumActionCheck(conclusions,
                        resource.getResourceClass(), resource.getActionFamily(), MinimumActionRules.Settings.DEFAULTS);
        boolean applies = !MinimumActionRules.evaluate(conclusions, resource.getResourceClass(),
                resource.getActionFamily(), MinimumActionRules.Settings.DEFAULTS).isEmpty();

        SecurityDecisionV1OutputInspector.V1Inspection allow = inspect(render, "ALLOW",
                new SecurityDecisionV1OutputInspector.V1Rules(conclusions, false, floors, false));
        SecurityDecisionV1OutputInspector.V1Inspection escalate = inspect(render, "ESCALATE",
                new SecurityDecisionV1OutputInspector.V1Rules(conclusions, false, floors, false));

        assertThat(applies).as("the golden case meets a minimum action rule").isTrue();
        assertThat(allow.ruleViolation()).startsWith(SecurityDecisionV1OutputInspector.MINIMUM_ACTION_VIOLATION);
        assertThat(escalate.ruleViolation()).isNull();
    }

    @Test
    void aReasonOnPastRecordsOfTheSameTargetNeedsAPastRecordLine() {
        SecurityDecisionFactChecks.DrawnPrompt none = SecurityDecisionFactChecks.DrawnPrompt.of(
                "=== PAST RECORDS ===\nPastRecordsState: none found (AVAILABLE)\n");
        SecurityDecisionFactChecks.DrawnPrompt drawn = SecurityDecisionFactChecks.DrawnPrompt.of(render().userPrompt());
        String reason = "Earlier allowed records on the same target show this is the user's usual work.";

        assertThat(SecurityDecisionFactChecks.pastRecordClaimViolation(none, reason))
                .isEqualTo(SecurityDecisionFactChecks.FALSE_PAST_RECORD_CLAIM);
        assertThat(SecurityDecisionFactChecks.pastRecordClaimViolation(none, "The device is new to the user."))
                .isNull();
        assertThat(SecurityDecisionFactChecks.pastRecordClaimViolation(drawn, reason)).isNull();
    }

    private static InspectionGolden.Render render() {
        return SecurityDecisionV1BundleTest.render(MeasuredVariant.FALLBACK_EXACT, context -> {
        });
    }

    private SecurityDecisionV1OutputInspector.V1Inspection inspect(InspectionGolden.Render render, String action,
                                                                   SecurityDecisionV1OutputInspector.V1Rules rules) {
        String answer = "{\"action\":\"" + action + "\",\"hypotheses\":[],\"reasonCodes\":[],"
                + "\"reason\":\"The facts were weighed.\",\"riskScore\":null,\"confidence\":null,\"mitre\":[]}";
        return inspector.inspect(answer, "req-v1", "initial",
                new SecurityDecisionV21OutputInspector.V21Check(render.used(), render.userPrompt(), false), rules);
    }
}
