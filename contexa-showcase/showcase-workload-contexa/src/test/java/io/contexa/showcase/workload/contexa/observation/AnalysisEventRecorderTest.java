package io.contexa.showcase.workload.contexa.observation;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Each layer's own reasoning is kept with its completion event, so the portal can show what the model wrote next to
 * the sentence the platform recorded as the final decision (docs/showcase/데모-재설계.md F-15, F-21).
 */
class AnalysisEventRecorderTest {

    private static final Map<String, Object> REQUEST = Map.of("requestId", "req-1");

    @Test
    void keepsEachLayersReasoningWithItsCompletion() {
        AnalysisEventRecorder recorder = new AnalysisEventRecorder(
                Clock.fixed(Instant.parse("2026-10-06T00:00:00Z"), ZoneOffset.UTC));

        recorder.onContextCollected("user", "/api/projects/GB-500/exports", REQUEST);
        recorder.onLayer1Start("user", "/api/projects/GB-500/exports", REQUEST);
        recorder.onLayer1Complete("user", "ESCALATE", 0.6, 0.5, "Layer one model sentence.", "none", 1800L, REQUEST);
        recorder.onLayer2Start("user", "/api/projects/GB-500/exports", "ambiguous", REQUEST);
        recorder.onLayer2Complete("user", "BLOCK", 0.9, 0.8, "Layer two model sentence.", "T1567", 2400L, REQUEST);
        recorder.onDecisionApplied("user", "BLOCK", "LAYER2", "/api/projects/GB-500/exports", REQUEST);

        List<AnalysisEventRecorder.AnalysisEvent> events = recorder.eventsOf("req-1");
        assertThat(events).extracting(AnalysisEventRecorder.AnalysisEvent::type).containsExactly("CONTEXT_COLLECTED",
                "LAYER1_START", "LAYER1_COMPLETE", "LAYER2_START", "LAYER2_COMPLETE", "DECISION_APPLIED");
        assertThat(events.get(2).reasoning()).isEqualTo("Layer one model sentence.");
        assertThat(events.get(2).mitre()).as("the engine's \"none\" is stored as absent").isNull();
        assertThat(events.get(4).reasoning()).isEqualTo("Layer two model sentence.");
        assertThat(events.get(4).mitre()).isEqualTo("T1567");
        assertThat(events).filteredOn(event -> !event.type().endsWith("_COMPLETE"))
                .allSatisfy(event -> assertThat(event.reasoning()).isNull());
    }
}
