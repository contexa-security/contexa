package io.contexa.showcase.portal.scenario;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent Agent중심-화면 AC-5 (D-6): the reference agent runs are frozen as files, so a visitor can see a real run
 * of an agent case without a model call, whatever the database holds. The portal serves them as they were read from
 * the running portal (the case and the run), and nothing else.
 */
class AgentSnapshotsControllerTest {

    private final AgentSnapshotsController controller = new AgentSnapshotsController(new ObjectMapper());

    @SuppressWarnings("unchecked")
    private Map<String, Object> summaryOf(String label) {
        Map<String, Object> snapshot = controller.snapshot(label).getBody();
        assertThat(snapshot).isNotNull();
        return (Map<String, Object>) snapshot.get("summary");
    }

    @Test
    void theIndexListsEveryFrozenRunWithItsCaseAndKind() {
        List<Map<String, Object>> index = controller.index();

        assertThat(index).extracting(entry -> entry.get("label")).contains("T5-confirm-approve", "M19A-delegated",
                "M41A-flights-on", "M41A-flights-off", "M41T-flights-on", "M41X-flights-off");
        assertThat(index).allSatisfy(entry -> assertThat(entry).containsKeys("label", "runId", "caseKey", "kind", "why"));
        assertThat(index).filteredOn(entry -> "T5".equals(entry.get("caseKey"))).hasSize(2);
    }

    @Test
    void aSnapshotIsTheCaseAndTheRunAsTheyWereRead() {
        ResponseEntity<Map<String, Object>> found = controller.snapshot("T5-confirm-approve");

        assertThat(found.getStatusCode().value()).isEqualTo(200);
        Map<String, Object> snapshot = found.getBody();
        assertThat(snapshot).containsKeys("label", "runId", "caseKey", "kind", "why", "capturedAt", "case", "run");
        assertThat(snapshot.get("runId")).isEqualTo("run-d2ca817d4929");
        assertThat(((Map<?, ?>) snapshot.get("run")).get("stopReason")).isEqualTo("ANSWERED");
    }

    /**
     * docs/agent Agent중심-화면 AS-10: what a burst did, counted by the portal from the stored run (the screens show the
     * counts and never make them): requests, what control D delivered and refused, the refusals that only said the
     * analysis was busy, the requests that have a verdict of their own, the model calls, and what was delivered after
     * the first stop.
     */
    @Test
    void aSnapshotCarriesTheCountsOfItsBurstMadeFromTheStoredRun() {
        assertThat(summaryOf("M41A-flights-on")).containsEntry("requests", 66).containsEntry("delivered", 66)
                .containsEntry("refused", 0).containsEntry("busy", 0).containsEntry("withVerdict", 6)
                .containsEntry("modelCalls", 7).containsEntry("deliveredAfterFirstStop", 0)
                .containsEntry("firstStopStep", null);
        assertThat(summaryOf("M41A-flights-off")).containsEntry("requests", 66).containsEntry("withVerdict", 66)
                .containsEntry("modelCalls", 129);
        assertThat(summaryOf("M41T-flights-on")).containsEntry("requests", 74).containsEntry("delivered", 2)
                .containsEntry("refused", 72).containsEntry("busy", 17).containsEntry("withVerdict", 4)
                .containsEntry("modelCalls", 4).containsEntry("firstStopStep", 42)
                .containsEntry("deliveredAfterFirstStop", 0);
        assertThat(summaryOf("M41X-flights-on")).containsEntry("requests", 36).containsEntry("refused", 35)
                .containsEntry("firstStopStep", 32);
    }

    @Test
    void aLabelOutsideTheIndexIsNotFoundAndANameOutsideTheShapeIsRefused() {
        assertThat(controller.snapshot("T5-nothing").getStatusCode().value()).isEqualTo(404);
        for (String bad : new String[]{"../application", "T5/../index", "..", "a b", "index"}) {
            assertThat(controller.snapshot(bad).getStatusCode().value()).as(bad).isIn(400, 404);
        }
    }
}
