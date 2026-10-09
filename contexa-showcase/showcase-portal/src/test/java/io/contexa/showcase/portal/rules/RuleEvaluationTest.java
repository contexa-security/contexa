package io.contexa.showcase.portal.rules;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** H-10: the settings the rules scene sends and how a case's result is read from the rule classes' decisions. */
class RuleEvaluationTest {

    private static RuleEvaluation.Settings settings(int start, int end, int volume, Integer assignedLimit) {
        return new RuleEvaluation.Settings(start, end, volume, true, true, true, true, true, true, assignedLimit,
                true);
    }

    @Test
    void settingsOutsideTheScenesRangeAreRefused() {
        assertThat(settings(22, 6, 500, null).valid()).isTrue();
        assertThat(settings(24, 6, 500, null).valid()).isFalse();
        assertThat(settings(22, -1, 500, null).valid()).isFalse();
        assertThat(settings(22, 6, -1, null).valid()).isFalse();
        assertThat(settings(22, 6, 500, RuleEvaluation.MAX_ITEMS + 1).valid()).isFalse();
    }

    @Test
    void theRuleClassesReceiveCompanyTimesAndTheCompanyLimitWhenNoneIsSet() {
        assertThat(settings(3, 6, 500, null).forRules()).containsEntry("nightStart", "03:00")
                .containsEntry("nightEnd", "06:00").containsEntry("assignedLimit", null);
    }

    private static RuleEvaluation.StepResult step(Boolean c1, Boolean c2) {
        return new RuleEvaluation.StepResult(1, new RuleEvaluation.Decision("C1", c1, c1 == null ? "network" : null,
                false), new RuleEvaluation.Decision("C2", c2, c2 == null ? "network" : null, false));
    }

    @Test
    void aCaseIsStoppedByAnyRefusalAndUnknownOnlyWithoutOne() {
        assertThat(RuleEvaluation.stopped(List.of(step(true, true), step(true, false)))).isTrue();
        assertThat(RuleEvaluation.stopped(List.of(step(null, true), step(false, true))))
                .as("a refusal decides even next to a request that could not be decided").isTrue();
        assertThat(RuleEvaluation.stopped(List.of(step(true, null)))).isNull();
        assertThat(RuleEvaluation.stopped(List.of(step(true, true)))).isFalse();
    }

    @Test
    void eachRuleControlIsReadOnItsOwnDecisions() {
        List<RuleEvaluation.StepResult> steps = List.of(step(true, false), step(null, true));
        assertThat(RuleEvaluation.stoppedBy(steps, RuleEvaluation.StepResult::c1))
                .as("the threshold rule refused nothing and could not decide one request").isNull();
        assertThat(RuleEvaluation.stoppedBy(steps, RuleEvaluation.StepResult::c2)).isTrue();
        assertThat(RuleEvaluation.stoppedBy(List.of(step(true, true)), RuleEvaluation.StepResult::c1)).isFalse();
    }

    private static RuleEvaluation.CaseResult result(String scenario, String classification, Boolean c1, Boolean c2) {
        return new RuleEvaluation.CaseResult(scenario, classification, null, c1, c2, List.of());
    }

    private static RuleCases.Case recorded(String scenario, String classification, String... outcomes) {
        List<RuleCases.CaseStep> steps = new ArrayList<>();
        for (int i = 0; i < outcomes.length; i++) {
            steps.add(new RuleCases.CaseStep(i + 1, "EXPORT", null, Map.of(), null, null, Map.of(), null, null,
                    outcomes[i], null));
        }
        return new RuleCases.Case(scenario, classification, Map.of(), "run-" + scenario, null, steps);
    }

    @Test
    void theServerCountsStoppedAttacksAndBlockedWorkPerApproach() {
        List<RuleEvaluation.CaseResult> results = List.of(result("A3", "THREAT", true, true),
                result("A6", "THREAT", false, true), result("A3T", "NORMAL", true, false),
                result("A6T", "NORMAL", false, null), result("U1", "UNCERTAIN", true, true));
        List<RuleCases.Case> recorded = List.of(recorded("A3", "THREAT", "HELD"),
                recorded("A6", "THREAT", "DELIVERED", "DELIVERED"), recorded("A3T", "NORMAL", "HELD"),
                recorded("A6T", "NORMAL", "DELIVERED", "STOPPED"), recorded("U1", "UNCERTAIN", "STOPPED"));

        Map<String, RuleEvaluation.Tally> tallies = RuleEvaluation.tallies(recorded, results);

        assertThat(tallies.get("C1")).isEqualTo(new RuleEvaluation.Tally(2, 1, 2, 1, 0, 0));
        assertThat(tallies.get("C2")).as("a case the rule could not decide is counted apart")
                .isEqualTo(new RuleEvaluation.Tally(2, 2, 1, 0, 0, 1));
        assertThat(tallies.get("D")).as("a held attack is stopped; a held normal task is checked, a stopped one blocked")
                .isEqualTo(new RuleEvaluation.Tally(2, 1, 2, 1, 1, 0));
    }

    @Test
    void onlyTheCasesWhoseResultMovedFromThePublishedSettingsAreListed() {
        List<RuleEvaluation.CaseResult> published = List.of(result("A3", "THREAT", true, true),
                result("A3T", "NORMAL", true, false));
        List<RuleEvaluation.CaseResult> now = List.of(result("A3", "THREAT", false, true),
                result("A3T", "NORMAL", true, false));

        assertThat(RuleEvaluation.changes(published, now)).containsExactly(
                new RuleEvaluation.Change("A3", "THREAT", "C1", true, false));
        assertThat(RuleEvaluation.changes(published, published)).isEmpty();
    }
}
