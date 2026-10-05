package io.contexa.showcase.workload.contexa.observation;

import io.contexa.contexacore.autonomous.event.LlmAnalysisEventObserver;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Records the analysis events the engine announces for each decision id: stages, candidate actions with risk,
 * confidence and MITRE technique, the applied decision, and escalation protection triggers per user. The portal reads
 * them for the analysis timeline (deck p.12) and the isolation test T1. The engine passes MITRE as the technique id or
 * the text "none"; "none" is stored as absent (reuse-assets 3.2).
 */
public class AnalysisEventRecorder implements LlmAnalysisEventObserver {

    static final int MAX_KEYS = 20_000;

    public record AnalysisEvent(String type, Instant observedAt, String action, Double riskScore, Double confidence,
                                String mitre, Long elapsedMs, String layer, String detail) {
    }

    private final Clock clock;
    private final Map<String, List<AnalysisEvent>> byDecision = bounded();
    private final Map<String, List<AnalysisEvent>> escalationProtectionByUser = bounded();

    public AnalysisEventRecorder(Clock clock) {
        this.clock = clock;
    }

    @Override
    public void onContextCollected(String userId, String requestPath, Map<String, Object> metadata) {
        add(metadata, new AnalysisEvent("CONTEXT_COLLECTED", clock.instant(), null, null, null, null, null, null,
                requestPath));
    }

    @Override
    public void onLayer1Start(String userId, String requestPath, Map<String, Object> metadata) {
        add(metadata, new AnalysisEvent("LAYER1_START", clock.instant(), null, null, null, null, null, "LAYER1", null));
    }

    @Override
    public void onLayer1Complete(String userId, String action, Double riskScore, Double confidence, String reasoning,
                                 String mitre, Long elapsedMs, Map<String, Object> metadata) {
        add(metadata, new AnalysisEvent("LAYER1_COMPLETE", clock.instant(), action, riskScore, confidence,
                mitre(mitre), elapsedMs, "LAYER1", null));
    }

    @Override
    public void onLayer2Start(String userId, String requestPath, String reason, Map<String, Object> metadata) {
        add(metadata, new AnalysisEvent("LAYER2_START", clock.instant(), null, null, null, null, null, "LAYER2", reason));
    }

    @Override
    public void onLayer2Complete(String userId, String action, Double riskScore, Double confidence, String reasoning,
                                 String mitre, Long elapsedMs, Map<String, Object> metadata) {
        add(metadata, new AnalysisEvent("LAYER2_COMPLETE", clock.instant(), action, riskScore, confidence,
                mitre(mitre), elapsedMs, "LAYER2", null));
    }

    @Override
    public void onDecisionApplied(String userId, String action, String layer, String requestPath,
                                  Map<String, Object> metadata) {
        add(metadata, new AnalysisEvent("DECISION_APPLIED", clock.instant(), action, null, null, null, null, layer,
                null));
    }

    @Override
    public void onError(String userId, String message, Map<String, Object> metadata) {
        add(metadata, new AnalysisEvent("ANALYSIS_ERROR", clock.instant(), null, null, null, null, null, null, message));
    }

    @Override
    public void onEscalateProtectionTriggered(String userId, String requestPath, int escalateCount,
                                              int totalAnalysisCount) {
        if (userId == null) {
            return;
        }
        synchronized (escalationProtectionByUser) {
            escalationProtectionByUser.computeIfAbsent(userId, key -> new ArrayList<>()).add(new AnalysisEvent(
                    "ESCALATE_PROTECTION", clock.instant(), null, null, null, null, null, null,
                    requestPath + " " + escalateCount + "/" + totalAnalysisCount));
        }
    }

    public List<AnalysisEvent> eventsOf(String decisionId) {
        synchronized (byDecision) {
            List<AnalysisEvent> events = byDecision.get(decisionId);
            return events == null ? List.of() : List.copyOf(events);
        }
    }

    public List<AnalysisEvent> escalationProtectionOf(String userId) {
        synchronized (escalationProtectionByUser) {
            List<AnalysisEvent> events = escalationProtectionByUser.get(userId);
            return events == null ? List.of() : List.copyOf(events);
        }
    }

    private void add(Map<String, Object> metadata, AnalysisEvent event) {
        Object requestId = metadata == null ? null : metadata.get("requestId");
        if (requestId == null) {
            return;
        }
        synchronized (byDecision) {
            byDecision.computeIfAbsent(requestId.toString(), key -> new ArrayList<>()).add(event);
        }
    }

    private static String mitre(String mitre) {
        return mitre == null || mitre.isBlank() || "none".equalsIgnoreCase(mitre) ? null : mitre;
    }

    private static Map<String, List<AnalysisEvent>> bounded() {
        return new LinkedHashMap<>(256, 0.75f, false) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, List<AnalysisEvent>> eldest) {
                return size() > MAX_KEYS;
            }
        };
    }
}
