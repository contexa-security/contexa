package io.contexa.showcase.portal.benchmark;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * W6-2 (P6-CHANGE-3, plan 2 A3, R1, C3): the decision quality of a measurement with its Wilson 95% intervals, by the
 * definitions of the measurement tools. A3: decisions with a final action on cases whose oracle names the correct
 * actions, correct when the action is one of them (prompt-audit/p1gate_decision_metrics.py). R1: case steps decided
 * more than once with a final action, consistent when every one took the same action (the accuracy tool). C3: decisions
 * whose seal the inspector's REASON_MATCH compared, agreeing when none of their reason codes mismatched. Forced
 * decisions are left out of all three.
 */
public record DecisionQuality(BenchmarkView.Rate accuracy, BenchmarkView.Rate consistency,
                              BenchmarkView.Rate reasonMatch, int forcedExcluded) {

    /** One decision of the measurement: its request, case step, final action and the case's correct actions. */
    public record Decision(String requestId, String caseKey, int stepNo, String finalAction,
                           List<String> allowedActions, boolean forced) {
    }

    /** The inspector's REASON_MATCH counts of a decision's seal. */
    public record ReasonMatch(int matched, int mismatched) {
    }

    public static DecisionQuality of(List<Decision> decisions, Map<String, ReasonMatch> reasons) {
        List<Decision> measured = decisions.stream().filter(decision -> !decision.forced()).toList();
        List<Decision> oracle = measured.stream()
                .filter(decision -> decision.allowedActions() != null && decision.finalAction() != null).toList();
        long correct = oracle.stream().filter(decision -> decision.allowedActions().contains(decision.finalAction()))
                .count();
        Map<String, List<String>> steps = new LinkedHashMap<>();
        for (Decision decision : measured) {
            // N-DQ-1: a step decided without a final action (no model call) is not a repeat of the measure.
            if (decision.finalAction() == null) {
                continue;
            }
            steps.computeIfAbsent(decision.caseKey() + "#" + decision.stepNo(), key -> new ArrayList<>())
                    .add(decision.finalAction());
        }
        long repeated = steps.values().stream().filter(actions -> actions.size() > 1).count();
        long consistent = steps.values().stream().filter(actions -> actions.size() > 1)
                .filter(actions -> actions.stream().allMatch(action -> Objects.equals(action, actions.get(0))))
                .count();
        long compared = 0;
        long agreeing = 0;
        for (Decision decision : measured) {
            ReasonMatch match = reasons.get(decision.requestId());
            if (match == null || match.matched() + match.mismatched() == 0) {
                continue;
            }
            compared++;
            if (match.mismatched() == 0) {
                agreeing++;
            }
        }
        return new DecisionQuality(BenchmarkService.rate(correct, oracle.size()),
                BenchmarkService.rate(consistent, repeated), BenchmarkService.rate(agreeing, compared),
                decisions.size() - measured.size());
    }
}
