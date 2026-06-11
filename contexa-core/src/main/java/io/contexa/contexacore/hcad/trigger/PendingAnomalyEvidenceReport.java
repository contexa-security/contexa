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
package io.contexa.contexacore.hcad.trigger;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public record PendingAnomalyEvidenceReport(
        boolean shouldTrigger,
        String userId,
        String contextBindingHash,
        String triggerStateKey,
        String requestId,
        String sessionId,
        String requestPath,
        String httpMethod,
        String clientIp,
        int escalationScore,
        String escalationBand,
        boolean escalationEligible,
        String escalationVersion,
        List<String> anchorSignals,
        List<String> corroboratingSignals,
        List<String> reasonCodes,
        String reasonSummary,
        String riskSignature,
        Map<String, Object> rawSignalSnapshot
) {

    public PendingAnomalyEvidenceReport {
        escalationBand = escalationBand == null ? "LOW" : escalationBand;
        escalationVersion = escalationVersion == null ? "hcad-promotion-v1" : escalationVersion;
        anchorSignals = anchorSignals == null ? List.of() : List.copyOf(anchorSignals);
        corroboratingSignals = corroboratingSignals == null ? List.of() : List.copyOf(corroboratingSignals);
        reasonCodes = reasonCodes == null ? List.of() : List.copyOf(reasonCodes);
        reasonSummary = reasonSummary == null ? "" : reasonSummary;
        rawSignalSnapshot = rawSignalSnapshot == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(rawSignalSnapshot));
    }

    public static PendingAnomalyEvidenceReport noTrigger(
            String userId,
            String contextBindingHash,
            String triggerStateKey,
            String requestId,
            String sessionId,
            String requestPath,
            String httpMethod,
            String clientIp,
            int escalationScore,
            String escalationBand,
            boolean escalationEligible,
            String escalationVersion,
            List<String> anchorSignals,
            List<String> corroboratingSignals,
            List<String> reasonCodes,
            String reasonSummary,
            Map<String, Object> rawSignalSnapshot) {
        return new PendingAnomalyEvidenceReport(
                false,
                userId,
                contextBindingHash,
                triggerStateKey,
                requestId,
                sessionId,
                requestPath,
                httpMethod,
                clientIp,
                escalationScore,
                escalationBand,
                escalationEligible,
                escalationVersion,
                anchorSignals,
                corroboratingSignals,
                reasonCodes,
                reasonSummary,
                null,
                rawSignalSnapshot
        );
    }
}