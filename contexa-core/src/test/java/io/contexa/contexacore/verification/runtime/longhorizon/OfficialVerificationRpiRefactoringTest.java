package io.contexa.contexacore.verification.runtime.longhorizon;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class OfficialVerificationRpiRefactoringTest {

    private final OfficialVerificationRpiRoundPlanFactory roundPlanFactory =
            new OfficialVerificationRpiRoundPlanFactory();
    private final OfficialVerificationRpiCheckEvaluator checkEvaluator =
            new OfficialVerificationRpiCheckEvaluator();

    @Test
    void preservesOfficialExtendedScenarioPlansAndProgressionChecks() {
        List<ProgressionRoundPlan> plans = roundPlanFactory.buildRoundPlans("admin", 3);

        assertThat(roundPlanFactory.minimumRounds()).isEqualTo(3);
        assertThat(roundPlanFactory.contractStatus(3)).isNotNull();
        assertThat(plans).isNotEmpty();
        assertThat(plans).extracting(ProgressionRoundPlan::scenarioKey).doesNotContainNull();

        List<RoundSnapshot> rounds = plans.stream().map(plan -> new RoundSnapshot(
                plan,
                plan.roundNumber(),
                "request-" + plan.scenarioIndex() + "-" + plan.roundNumber(),
                Map.of("requestId", "request-" + plan.scenarioIndex() + "-" + plan.roundNumber()),
                List.of(),
                null,
                null,
                Map.of(),
                Map.of(),
                Map.of(),
                Map.of(),
                Map.of(),
                Math.min(2, plan.roundNumber() - 1),
                plan.roundNumber(),
                true,
                true,
                "Observations " + plan.roundNumber()
        )).toList();

        assertThat(checkEvaluator.buildChecks(rounds))
                .isNotEmpty()
                .allMatch(OfficialVerificationRpiExecutionService.RpiCheckResult::pass);
    }
}
