package io.contexa.contexacore.verification.runtime.longhorizon;

import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.verification.contract.prompt.OfficialVerificationPromptContractSessionMode;
import io.contexa.contexacore.verification.runtime.OfficialVerificationAnalysisEventStore;

import java.time.Instant;
import java.util.List;
import java.util.Map;

record RequestedTarget(String endpointKey, String resourceId, String requestPath) {
}

record ProgressionRoundPlan(
        String scenarioKey,
        String scenarioFamily,
        String scenarioHeader,
        String expectedActionHeader,
        String roundKey,
        String benchmarkRunId,
        String verificationUserId,
        String sessionId,
        int scenarioIndex,
        int roundNumber,
        String endpointKey,
        String endpointLabel,
        String resourceId,
        String requestPath,
        String clientIp,
        String browserUserAgent,
        String simulatedUserAgentLabel,
        String deviceAlias,
        String deviceId,
        Instant observedAt,
        OfficialVerificationPromptContractSessionMode sessionMode,
        long cooldownBeforeRoundMs,
        String behaviorPhase,
        String anomalySignal,
        String note,
        List<String> semanticMarkers
) {
    boolean initialRound() {
        return roundNumber == 1;
    }

    boolean evaluationRound() {
        return true;
    }
}

record RoundSnapshot(
        ProgressionRoundPlan plan,
        int roundNumber,
        String requestId,
        Map<String, Object> invocation,
        List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events,
        SecurityDecisionForwardingOutboxRecord decisionOutbox,
        PromptContextAuditForwardingOutboxRecord promptOutbox,
        Map<String, Object> decisionPayload,
        Map<String, Object> promptPayload,
        Map<String, Object> decisionMetadata,
        Map<String, Object> decisionAttributes,
        Map<String, Object> promptTelemetry,
        int relatedDocumentsCount,
        int observationCount,
        boolean baselineContextPresent,
        boolean requestParityAligned,
        String workProfileSummary
) {
}
