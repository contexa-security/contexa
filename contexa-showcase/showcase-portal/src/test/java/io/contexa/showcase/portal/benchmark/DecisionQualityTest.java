package io.contexa.showcase.portal.benchmark;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W6-2 (P6-CHANGE-3): the decision quality of a measurement with its Wilson intervals, by the definitions of the
 * measurement tools: A3 correct decisions on oracle cases (prompt-audit/p1gate_decision_metrics.py), R1 repeat
 * consistency per case step (the accuracy tool's consistency), C3 reason codes matching their facts (the inspector's
 * REASON_MATCH). Forced decisions are left out.
 */
class DecisionQualityTest {

    @Test
    void theThreeMeasuresAreCountedFromTheDecisions() {
        List<DecisionQuality.Decision> decisions = List.of(
                decision("r1", "A3", 1, "CHALLENGE", List.of("BLOCK", "CHALLENGE", "ESCALATE"), false),
                decision("r2", "A3", 1, "CHALLENGE", List.of("BLOCK", "CHALLENGE", "ESCALATE"), false),
                decision("r3", "A3", 1, "ALLOW", List.of("BLOCK", "CHALLENGE", "ESCALATE"), false),
                decision("r4", "A3T", 1, "ALLOW", List.of("ALLOW"), false),
                decision("r5", "A3T", 1, "ALLOW", List.of("ALLOW"), false),
                decision("r6", "A3T", 1, "BLOCK", List.of("ALLOW"), true),
                decision("r7", "S08", 1, "ESCALATE", null, false));
        Map<String, DecisionQuality.ReasonMatch> reasons = Map.of(
                "r1", new DecisionQuality.ReasonMatch(3, 0), "r2", new DecisionQuality.ReasonMatch(2, 1),
                "r4", new DecisionQuality.ReasonMatch(0, 0));

        DecisionQuality quality = DecisionQuality.of(decisions, reasons);

        assertThat(quality.accuracy().hits()).isEqualTo(4);
        assertThat(quality.accuracy().total()).isEqualTo(5);
        assertThat(quality.consistency().hits()).isEqualTo(1);
        assertThat(quality.consistency().total()).isEqualTo(2);
        assertThat(quality.reasonMatch().hits()).isEqualTo(1);
        assertThat(quality.reasonMatch().total()).isEqualTo(2);
        assertThat(quality.accuracy().low()).isNotNull();
        assertThat(quality.forcedExcluded()).isEqualTo(1);
    }

    @Test
    void aStepDecidedWithoutAFinalActionIsNotARepeatOfTheMeasure() {
        List<DecisionQuality.Decision> decisions = List.of(
                decision("r1", "R1", 1, null, null, false),
                decision("r2", "R1", 1, null, null, false),
                decision("r3", "A6", 2, null, null, false),
                decision("r4", "A6", 2, "CHALLENGE", null, false),
                decision("r5", "A3", 1, "CHALLENGE", null, false),
                decision("r6", "A3", 1, "ESCALATE", null, false));

        DecisionQuality quality = DecisionQuality.of(decisions, Map.of());

        assertThat(quality.consistency().total()).isEqualTo(1);
        assertThat(quality.consistency().hits()).isZero();
    }

    private static DecisionQuality.Decision decision(String requestId, String caseKey, int step, String action,
                                                     List<String> allowed, boolean forced) {
        return new DecisionQuality.Decision(requestId, caseKey, step, action, allowed, forced);
    }
}
