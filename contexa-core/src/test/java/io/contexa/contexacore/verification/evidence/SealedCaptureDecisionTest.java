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
package io.contexa.contexacore.verification.evidence;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.monitoring.ai.DecisionConsoleColumns;
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plan 3.6: what the capture knows of a decision when it chooses whether to seal it, read from the event and the
 * processing result as the decision record reads its columns.
 */
class SealedCaptureDecisionTest {

    @Test
    void theActionAndTheSignsAreReadAsTheDecisionRecordReadsItsColumns() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("learningPersonalBaselineEstablished", false);
        metadata.put("promptEvidenceCompletenessReasons", List.of("approval", "duty", "assignment"));
        metadata.put(PromptRuntimeTelemetrySupport.OUTPUT_RETRIES, List.of(Map.of("layer", "Layer1")));
        ProcessingResult result = result("allow", 2,
                List.of(Map.of("id", "H1", "assessment", "POSSIBLE"), Map.of("id", "h3", "assessment", "MOST_LIKELY")));

        SealedCaptureDecision decision = SealedCaptureDecision.of(context(metadata, result));

        assertThat(decision.action()).isEqualTo("ALLOW");
        assertThat(decision.mostLikelyHypothesis()).isEqualTo("H3");
        assertThat(decision.secondAnalysis()).isTrue();
        assertThat(decision.askedAgain()).isTrue();
        assertThat(decision.unknownFactCount()).isEqualTo(3);
        assertThat(decision.baselineStatus()).isEqualTo("NONE");
        DecisionConsoleColumns.Values columns = DecisionConsoleColumns.of(metadata, result, ZeroTrustAction.ALLOW,
                Instant.now());
        assertThat(decision.mostLikelyHypothesis()).isEqualTo(columns.mostLikelyHypothesis());
        assertThat(decision.unknownFactCount()).isEqualTo(columns.unknownFactCount());
        assertThat(decision.baselineStatus()).isEqualTo(columns.baselineStatus());
        assertThat(decision.stopped()).isFalse();
        assertThat(decision.allowedWithRisk(3)).isTrue();
    }

    @Test
    void anOrdinaryAllowedDecisionCarriesNoSign() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("learningPersonalBaselineEstablished", true);
        metadata.put("promptEvidenceCompletenessReasons", List.of("approval"));
        ProcessingResult result = result("ALLOW", 1, List.of(Map.of("id", "H1", "assessment", "MOST_LIKELY")));

        SealedCaptureDecision decision = SealedCaptureDecision.of(context(metadata, result));

        assertThat(decision).isEqualTo(new SealedCaptureDecision("ALLOW", "H1", false, false, 1, "ESTABLISHED"));
        assertThat(decision.stopped()).isFalse();
        assertThat(decision.allowedWithRisk(3)).isFalse();
        assertThat(decision.allowedWithRisk(1)).as("one unknown fact reaches a threshold of one").isTrue();
    }

    @Test
    void aStopIsToldByTheActionTheDecisionEndedIn() {
        for (String action : List.of("CHALLENGE", "escalate", " Block ")) {
            SealedCaptureDecision decision = SealedCaptureDecision.of(context(new HashMap<>(), result(action, 1, null)));
            assertThat(decision.stopped()).as(action).isTrue();
            assertThat(decision.allowedWithRisk(1)).as("the signs are an allowed decision's").isFalse();
        }
        assertThat(SealedCaptureDecision.of(context(new HashMap<>(), result("PENDING_ANALYSIS", 0, null))).stopped())
                .isFalse();
    }

    /** A decision without a result, or with an action that is none, has no action and so no priority. */
    @Test
    void aDecisionWithoutAResultOrAnActionHasNeither() {
        SealedCaptureDecision withoutResult = SealedCaptureDecision.of(
                new SecurityEventContext(SecurityEvent.builder().eventId("evt-none").userId("alice").build()));
        SealedCaptureDecision blankAction = SealedCaptureDecision.of(context(new HashMap<>(), result(" ", 1, null)));

        assertThat(withoutResult).isEqualTo(new SealedCaptureDecision(null, null, false, false, null, null));
        assertThat(blankAction.action()).isNull();
        assertThat(withoutResult.stopped()).isFalse();
        assertThat(withoutResult.allowedWithRisk(1)).isFalse();
    }

    private static SecurityEventContext context(Map<String, Object> eventMetadata, ProcessingResult result) {
        SecurityEvent event = SecurityEvent.builder().eventId("evt-1").userId("alice").build();
        event.setMetadata(eventMetadata);
        SecurityEventContext context = new SecurityEventContext(event);
        context.addMetadata("processingResult", result);
        return context;
    }

    private static ProcessingResult result(String action, int analysisLevel, List<Map<String, Object>> hypotheses) {
        ProcessingResult result = ProcessingResult.builder().success(true).build();
        result.setAction(action);
        result.setAiAnalysisLevel(analysisLevel);
        result.setHypotheses(hypotheses);
        return result;
    }
}
