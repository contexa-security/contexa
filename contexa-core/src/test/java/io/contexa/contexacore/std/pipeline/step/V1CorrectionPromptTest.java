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
package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.PromptAssembler;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocumentReader;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionV1OutputInspector;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.messages.Message;
import org.springframework.ai.chat.messages.SystemMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.prompt.Prompt;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plan 6-1: the short v1.0 answer is asked again in the words of its prompt document. K31: the output contract
 * correction asks for the one explanation judged most likely, as the v5 answer gives it, not for explanations; K32: an
 * answer weaker than an enforced floor is asked for the floor or a stronger response; a version with the decision
 * rules (D6) is asked as the rules ask.
 */
class V1CorrectionPromptTest {

    private static final Prompt PROMPT = new Prompt(List.of(new SystemMessage("system"), new UserMessage("user")));

    @Test
    void k31TheContractCorrectionAsksForTheExplanationJudgedMostLikely() {
        String text = lastText(LLMExecutionStep.correctivePromptV1(PROMPT, "{\"action\":\"ALLOW\"}",
                "REASON_CODE_UNSUPPORTED: DEVIATION_DEVICE", SecurityDecisionPromptDocument.CORRECTION_CONTRACT, null));

        assertThat(text).isEqualTo("The previous answer did not follow the output contract or cited what the lines do"
                + " not state (REASON_CODE_UNSUPPORTED: DEVIATION_DEVICE). Answer again with one JSON object with"
                + " exactly these keys: action, riskScore, hypothesis, reasonCodes, reason. Start it with {\"action\":"
                + " and one of ALLOW, CHALLENGE, ESCALATE and BLOCK; give the explanation you judged most likely and"
                + " reason codes that cite only the lines that state them. Your action is yours to choose.");
        assertThat(text).doesNotContain("explanations and reason codes");
    }

    @Test
    void k32AnAnswerWeakerThanAnEnforcedFloorIsAskedForTheFloor() {
        SecurityDecisionV1OutputInspector.V1Inspection floor = new SecurityDecisionV1OutputInspector.V1Inspection(
                null, List.of(), false, SecurityDecisionV1OutputInspector.MINIMUM_ACTION_VIOLATION
                + ": MIN_P1_IDENTITY_DEVIATION requires CHALLENGE or a stronger action");
        SecurityDecisionV1OutputInspector.V1Inspection format = new SecurityDecisionV1OutputInspector.V1Inspection(
                null, List.of(), false, null);
        SecurityDecisionV1OutputInspector.V1Rules fallback = new SecurityDecisionV1OutputInspector.V1Rules(null, true,
                null, true);
        SecurityDecisionV1OutputInspector.V1Inspection boundary = new SecurityDecisionV1OutputInspector.V1Inspection(
                null, List.of(), false, "BOUNDARY_VIOLATION: Required BLOCK boundary");

        assertThat(LLMExecutionStep.correctionKey(floor, null))
                .isEqualTo(SecurityDecisionPromptDocument.CORRECTION_MINIMUM_ACTION);
        assertThat(LLMExecutionStep.correctionKey(floor, fallback))
                .isEqualTo(SecurityDecisionPromptDocument.CORRECTION_MINIMUM_ACTION);
        assertThat(LLMExecutionStep.correctionKey(boundary, fallback))
                .isEqualTo(SecurityDecisionPromptDocument.CORRECTION_RULES);
        assertThat(LLMExecutionStep.correctionKey(boundary, null))
                .isEqualTo(SecurityDecisionPromptDocument.CORRECTION_CONTRACT);
        assertThat(LLMExecutionStep.correctionKey(format, fallback))
                .isEqualTo(SecurityDecisionPromptDocument.CORRECTION_CONTRACT);

        String text = lastText(LLMExecutionStep.correctivePromptV1(PROMPT, "{}", floor.ruleViolation(),
                SecurityDecisionPromptDocument.CORRECTION_MINIMUM_ACTION, null));
        assertThat(text).startsWith("The previous answer chose a response weaker than the floor of a minimum action"
                        + " rule that applies (MINIMUM_ACTION_VIOLATION: MIN_P1_IDENTITY_DEVIATION requires CHALLENGE or"
                        + " a stronger action).")
                .contains("choose that floor or a stronger response").doesNotContain("Your action is yours to choose");
    }

    @Test
    void theCorrectionFollowsThePromptAndTheAnswerItGot() {
        Prompt corrected = LLMExecutionStep.correctivePromptV1(PROMPT, "{\"action\":\"BLOCK\"}", "X",
                SecurityDecisionPromptDocument.CORRECTION_RULES, null);
        List<Message> messages = corrected.getInstructions();

        assertThat(messages).hasSize(4);
        assertThat(messages.get(2).getText()).isEqualTo("{\"action\":\"BLOCK\"}");
        assertThat(messages.get(3).getText()).startsWith("The previous answer was rejected (X).");
    }

    /**
     * Plan 3.4: the correction is the one of the version the decision runs, which the strategy hands to the call; a
     * version of another product release asks in its own words.
     */
    @Test
    void theCorrectionIsTheOneOfTheVersionTheDecisionRuns() {
        AssembledPrompt later = new PromptAssembler().product(new PromptVersionDocumentReader().read(
                SecurityDecisionPromptDocument.resource("2026.11.16")
                        .replace("release: 2026.11.16-v1.0", "release: 2026.12.01-v1.1")
                        .replace("The previous answer did not follow the output contract",
                                "The earlier answer did not follow the output contract")));

        String text = lastText(LLMExecutionStep.correctivePromptV1(PROMPT, "{}", "X",
                SecurityDecisionPromptDocument.CORRECTION_CONTRACT, later));

        assertThat(text).startsWith("The earlier answer did not follow the output contract or cited what the lines do"
                + " not state (X).");
    }

    private static String lastText(Prompt prompt) {
        List<Message> messages = prompt.getInstructions();
        return messages.get(messages.size() - 1).getText();
    }
}
