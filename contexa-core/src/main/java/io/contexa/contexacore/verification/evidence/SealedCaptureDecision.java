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

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.monitoring.ai.DecisionConsoleColumns;
import io.contexa.contexacore.monitoring.ai.DecisionRiskSignals;

import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * What the capture knows of an enforced decision when it chooses whether to seal it: the action it ended in, and the
 * values that tell an allowed decision worth keeping from an ordinary one. The values are the decision record's own
 * columns ({@link DecisionConsoleColumns}), read from the same event and processing result, and the signs are those
 * of {@link DecisionRiskSignals}, so a decision the capture calls risky is one the review sample finds by the same
 * columns (quality plan 3.6: the allowed decisions are sealed and sampled for review by the same signs).
 *
 * @param action               the action the decision ended in, upper case; null when the result names none
 * @param mostLikelyHypothesis the explanation the model marked most likely ({@code H1} is legitimate work), or null
 * @param secondAnalysis       whether the second analysis decided (the analysis depth is 2)
 * @param askedAgain           whether the model was asked again: more model calls than one per layer that ran
 * @param unknownFactCount     how many decision facts were unknown, or null when the decision kept none
 * @param baselineStatus       the state of the personal baseline (ESTABLISHED, PROVISIONAL, NONE), or null when unknown
 */
public record SealedCaptureDecision(String action, String mostLikelyHypothesis, boolean secondAnalysis,
                                    boolean askedAgain, Integer unknownFactCount, String baselineStatus) {

    /** The explanation that the account owner is doing their own work, as the product's prompt names it. */
    public static final String LEGITIMATE_WORK = DecisionRiskSignals.LEGITIMATE_WORK;

    private static final Set<String> STOPPED = Set.of(ZeroTrustAction.CHALLENGE.name(), ZeroTrustAction.ESCALATE.name(),
            ZeroTrustAction.BLOCK.name());
    private static final String PROCESSING_RESULT = "processingResult";

    /** The decision of the event context as the capture handler copied it right after the enforcement. */
    public static SealedCaptureDecision of(SecurityEventContext context) {
        Map<String, Object> event = context.getSecurityEvent() != null ? context.getSecurityEvent().getMetadata() : null;
        ProcessingResult result = context.getMetadata() != null
                && context.getMetadata().get(PROCESSING_RESULT) instanceof ProcessingResult processed ? processed : null;
        String action = result != null && result.getAction() != null && !result.getAction().isBlank()
                ? result.getAction().trim().toUpperCase(Locale.ROOT) : null;
        DecisionConsoleColumns.Values columns = DecisionConsoleColumns.of(event, result, zeroTrustAction(action),
                Instant.now());
        return new SealedCaptureDecision(action, columns.mostLikelyHypothesis(),
                DecisionRiskSignals.secondAnalysis(columns.analysisDepth()),
                DecisionRiskSignals.askedAgain(columns.modelCallCount(), columns.decisionStage()),
                columns.unknownFactCount(), columns.baselineStatus());
    }

    /** Whether the decision stopped the request: CHALLENGE, ESCALATE or BLOCK. */
    public boolean stopped() {
        return action != null && STOPPED.contains(action);
    }

    /**
     * Whether the decision allowed the request while something about it says it may be a miss
     * ({@link DecisionRiskSignals}): the most likely explanation is not legitimate work, the second analysis had to
     * decide, the model was asked again, at least {@code unknownFactThreshold} decision facts were unknown, or the
     * personal baseline is not established. A value the decision did not keep is no signal.
     */
    public boolean allowedWithRisk(int unknownFactThreshold) {
        return !signals(unknownFactThreshold).isEmpty();
    }

    /** The signs of the allowed decision; none for a decision that did not allow. */
    public Set<DecisionRiskSignals.Signal> signals(int unknownFactThreshold) {
        return DecisionRiskSignals.of(action, mostLikelyHypothesis, secondAnalysis, askedAgain, unknownFactCount,
                baselineStatus, unknownFactThreshold);
    }

    private static ZeroTrustAction zeroTrustAction(String action) {
        if (action == null) {
            return null;
        }
        try {
            return ZeroTrustAction.valueOf(action);
        } catch (IllegalArgumentException unknown) {
            return null;
        }
    }
}
