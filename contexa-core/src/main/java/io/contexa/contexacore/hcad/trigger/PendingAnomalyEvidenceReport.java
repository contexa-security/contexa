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
        List<String> anchorSignals,
        List<String> corroboratingSignals,
        List<String> reasonCodes,
        String reasonSummary,
        String riskSignature,
        Map<String, Object> rawSignalSnapshot
) {

    public PendingAnomalyEvidenceReport {
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
                anchorSignals,
                corroboratingSignals,
                reasonCodes,
                reasonSummary,
                null,
                rawSignalSnapshot
        );
    }
}