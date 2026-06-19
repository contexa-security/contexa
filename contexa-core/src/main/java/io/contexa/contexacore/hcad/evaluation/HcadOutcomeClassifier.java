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
package io.contexa.contexacore.hcad.evaluation;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;

public final class HcadOutcomeClassifier {

    public static final String TRUE_POSITIVE = "TP";
    public static final String FALSE_POSITIVE = "FP";
    public static final String FALSE_NEGATIVE = "FN";
    public static final String TRUE_NEGATIVE = "TN";
    public static final String UNKNOWN = "UNKNOWN";

    private HcadOutcomeClassifier() {
    }

    public static String classifyHcadTriggered(ProcessingResult result, ZeroTrustAction enforcedAction) {
        return classify(result, enforcedAction, true);
    }

    public static String classifyHcadObservation(ProcessingResult result, ZeroTrustAction enforcedAction) {
        return classify(result, enforcedAction, false);
    }

    private static String classify(ProcessingResult result, ZeroTrustAction enforcedAction, boolean hcadTriggered) {
        if (!hasReliableLlmDecision(result)) {
            return UNKNOWN;
        }
        boolean risky = isRiskyDecision(result, enforcedAction);
        if (hcadTriggered) {
            return risky ? TRUE_POSITIVE : FALSE_POSITIVE;
        }
        return risky ? FALSE_NEGATIVE : TRUE_NEGATIVE;
    }

    private static boolean hasReliableLlmDecision(ProcessingResult result) {
        if (result == null || !result.isSuccess()) {
            return false;
        }
        if (Boolean.FALSE.equals(result.getLlmDecisionPresent())) {
            return false;
        }
        return !Boolean.TRUE.equals(result.getTechnicalFallbackApplied());
    }

    private static boolean isRiskyDecision(ProcessingResult result, ZeroTrustAction enforcedAction) {
        ZeroTrustAction semanticAction = resolveAction(result.getProposedAction());
        if (semanticAction == null) {
            semanticAction = resolveAction(result.getAction());
        }
        if (semanticAction == null) {
            semanticAction = enforcedAction;
        }
        return semanticAction != null && semanticAction != ZeroTrustAction.ALLOW;
    }

    private static ZeroTrustAction resolveAction(String action) {
        if (action == null || action.isBlank()) {
            return null;
        }
        return ZeroTrustAction.fromString(action);
    }
}
