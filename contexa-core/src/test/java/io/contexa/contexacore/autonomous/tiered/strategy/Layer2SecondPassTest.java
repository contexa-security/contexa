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
package io.contexa.contexacore.autonomous.tiered.strategy;

import io.contexa.contexacommon.domain.SecurityEvent;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** W3-9: what the first pass gives the second pass, and the facts only the second pass gathered. */
class Layer2SecondPassTest {

    @Test
    void theFirstPassIsReadFromTheLayer1AssessmentAndThePromptItLeft() {
        Layer2SecondPass.FirstPass first = Layer2SecondPass.FirstPass.of(event(assessment(true, false), "PROMPT",
                "v20-dictionary-blocks", "TIMEOUT"));

        assertThat(first.verdict()).isEqualTo("ESCALATE");
        assertThat(first.modelVerdict()).isTrue();
        assertThat(first.userPrompt()).isEqualTo("PROMPT");
        assertThat(first.pastRecordsState()).isEqualTo("TIMEOUT");
        assertThat(first.givesASecondPass()).isTrue();
    }

    @Test
    void aTechnicalFallbackOrAMissingAssessmentIsNoFirstVerdict() {
        assertThat(Layer2SecondPass.FirstPass.of(event(assessment(true, true), "PROMPT", "v20-dictionary-blocks",
                "TIMEOUT")).givesASecondPass()).isFalse();
        assertThat(Layer2SecondPass.FirstPass.of(event(assessment(false, false), "PROMPT", "v20-dictionary-blocks",
                "TIMEOUT")).givesASecondPass()).isFalse();
        assertThat(Layer2SecondPass.FirstPass.of(event(null, "PROMPT", "v20-dictionary-blocks", "TIMEOUT"))
                .givesASecondPass()).isFalse();
    }

    @Test
    void onlyAV20FirstPromptGivesASecondPass() {
        assertThat(Layer2SecondPass.FirstPass.of(event(assessment(true, false), "PROMPT", null, "TIMEOUT"))
                .givesASecondPass()).isFalse();
        assertThat(Layer2SecondPass.FirstPass.of(event(assessment(true, false), "PROMPT", "2026.10.11-v19.8", "TIMEOUT"))
                .givesASecondPass()).isFalse();
        assertThat(Layer2SecondPass.FirstPass.of(event(assessment(true, false), " ", "v20-dictionary-blocks", "TIMEOUT"))
                .givesASecondPass()).isFalse();
    }

    @Test
    void theNewPastRecordsAreTheOnesTheFirstPassCouldNotRetrieve() {
        List<Document> found = List.of(new Document("past record one"));
        for (String state : List.of("TIMEOUT", "BUDGET_EXPIRED", "UNAVAILABLE", "NOT_REQUESTED")) {
            assertThat(firstPass(state).newPastRecords(found)).as(state).containsExactlyElementsOf(found);
            assertThat(firstPass(state).newPastRecords(List.of())).as(state).isEmpty();
        }
        for (String state : List.of("AVAILABLE", "ZERO_RESULTS")) {
            assertThat(firstPass(state).newPastRecords(found)).as(state).isEmpty();
        }
    }

    private static Layer2SecondPass.FirstPass firstPass(String pastRecordsState) {
        return Layer2SecondPass.FirstPass.of(event(assessment(true, false), "PROMPT", "v20-dictionary-blocks",
                pastRecordsState));
    }

    private static Map<String, Object> assessment(boolean llmDecisionPresent, boolean technicalFallbackApplied) {
        return Map.of("llmAction", "ESCALATE", "llmDecisionPresent", llmDecisionPresent,
                "technicalFallbackApplied", technicalFallbackApplied, "reasoning", "Business intent remains uncertain.");
    }

    private static SecurityEvent event(Map<String, Object> assessment, String userPrompt, String layout,
                                       String pastRecordsState) {
        Map<String, Object> metadata = new HashMap<>();
        if (assessment != null) {
            metadata.put("layer1Assessment", assessment);
        }
        metadata.put("userPrompt", userPrompt);
        if (layout != null) {
            metadata.put("userPromptLayoutVersion", layout);
        }
        metadata.put("ragRetrievalState", pastRecordsState);
        return SecurityEvent.builder().eventId("w39-pure").userId("user-1").metadata(metadata).build();
    }
}
