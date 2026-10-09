package io.contexa.showcase.portal.lab;

import io.contexa.showcase.portal.anatomy.InputComparison;
import io.contexa.showcase.portal.replay.ReplayView;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** The lab's previous-against-this comparison is the server's: which approaches changed and whether Contexa did. */
class LabVersusControllerTest {

    private static LabVersusController.Side side(String c1, String d, String action, long exposed) {
        Map<String, String> outcomes = new LinkedHashMap<>();
        outcomes.put("A", "DELIVERED");
        outcomes.put("C1", c1);
        outcomes.put("D", d);
        return new LabVersusController.Side("run-x", "LAB-1", Map.of(), outcomes, action, exposed);
    }

    @Test
    void theChangedApproachesAndContexasChangeAreTheServersReading() {
        List<InputComparison.Change> inputs = List.of(new InputComparison.Change("ApprovalMissing", "true", "false"));
        LabVersusController.Versus versus = LabVersusController.compare(side("STOPPED", "HELD", "CHALLENGE", 0),
                side("STOPPED", "DELIVERED", "ALLOW", 4831), inputs, List.of("approval"));

        assertThat(versus.changedControls()).containsExactly("D");
        assertThat(versus.contexaChanged()).isTrue();
        assertThat(versus.inputs()).isEqualTo(inputs);
        assertThat(versus.changedConditions()).containsExactly("approval");
    }

    @Test
    void theChangedConditionsAreTheStoredValuesThatDiffer() {
        Map<String, Object> before = new LinkedHashMap<>();
        before.put("timeSlot", "03:17");
        before.put("approval", false);
        before.put("items", 4831);
        Map<String, Object> now = new LinkedHashMap<>(before);
        now.put("approval", true);

        assertThat(LabVersusController.changedConditions(before, now)).containsExactly("approval");
        assertThat(LabVersusController.changedConditions(before, before)).as("sent again as it was").isEmpty();
        now.put("onCall", true);
        assertThat(LabVersusController.changedConditions(before, now)).containsExactly("approval", "onCall");
    }

    @Test
    void aDifferentFirstDecisionCountsAsContexaChangingEvenWithTheSameResult() {
        assertThat(LabVersusController.compare(side("DELIVERED", "DELIVERED", "CHALLENGE", 4831),
                side("DELIVERED", "DELIVERED", "ALLOW", 4831), List.of(), null).contexaChanged()).isTrue();
        assertThat(LabVersusController.compare(side("DELIVERED", "DELIVERED", "ALLOW", 4831),
                side("DELIVERED", "DELIVERED", "ALLOW", 4831), List.of(), null).contexaChanged()).isFalse();
    }

    private static ReplayView.Layer layer(String control, String outcome) {
        return new ReplayView.Layer(control, outcome, null, null, null, null, Map.of(), null);
    }

    @Test
    void aRunsAnswerIsTheStrongestOverItsRequests() {
        Map<String, String> outcomes = LabVersusController.strongest(List.of(
                List.of(layer("C1", "DELIVERED"), layer("D", "HELD")),
                List.of(layer("C1", "STOPPED"), layer("D", "DELIVERED"))));

        assertThat(outcomes).containsEntry("C1", "STOPPED").as("a check held over a later delivery")
                .containsEntry("D", "HELD");
    }
}
