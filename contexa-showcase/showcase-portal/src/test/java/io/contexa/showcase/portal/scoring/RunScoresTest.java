package io.contexa.showcase.portal.scoring;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scoring.RunScores.Arm;
import io.contexa.showcase.portal.scoring.RunScores.Check;
import io.contexa.showcase.portal.scoring.RunScores.Decision;
import io.contexa.showcase.portal.scoring.RunScores.DecisionSource;
import io.contexa.showcase.portal.scoring.RunScores.RunRow;
import io.contexa.showcase.portal.scoring.RunScores.RunScore;
import io.contexa.showcase.portal.scoring.RunScores.TruthSource;
import io.contexa.showcase.portal.scoring.Scoring.BusinessResult;
import io.contexa.showcase.portal.scoring.Scoring.VerdictResult;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * How a stored run is scored (docs/showcase/데모-재설계.md 5.0, W1-1): the ground truth comes from the definition the
 * run executed, a step without a decision says why, and a run stopped before its last step is scored on what was
 * sent.
 */
class RunScoresTest {

    private final RunScores scores;

    RunScoresTest() throws IOException {
        ObjectMapper json = new ObjectMapper().findAndRegisterModules();
        this.scores = new RunScores(null, new ScenarioCatalog(json), json);
    }

    private static List<Arm> step(int stepNo, String d, Integer dStatus, long items, String dRule) {
        List<Arm> arms = new ArrayList<>();
        for (String control : List.of("A", "B", "C1", "C2")) {
            arms.add(new Arm(stepNo, control, "DELIVERED", 200, items, null));
        }
        arms.add(new Arm(stepNo, "D", d, dStatus, "DELIVERED".equals(d) ? items : 0, dRule));
        return arms;
    }

    /** S12 (C-2): a source mark states when the engine recorded its decision, and when the run ended. */
    @Test
    void theRecordedTimesOfTheDecisionAndTheRunTravelWithTheScore() {
        Instant decided = Instant.parse("2026-10-08T12:57:08.339Z");
        Instant finished = Instant.parse("2026-10-08T12:57:10.512Z");
        RunScore score = scores.score(new RunRow("run-7", "A3S", 1, "COMPLETED", null, finished),
                step(1, "HELD", 401, 4831, null), Map.of(),
                Map.of(1, new Decision(1, "CHALLENGE", "CHALLENGE", false, "BEFORE_RESPONSE", decided)));

        assertThat(score.verdicts()).singleElement().satisfies(verdict ->
                assertThat(verdict.decidedAt()).isEqualTo(decided));
        assertThat(score.finishedAt()).isEqualTo(finished);
        assertThat(scores.score(new RunRow("run-8", "A3S", 1, "RUNNING", null), step(1, "DELIVERED", 200, 40, null),
                Map.of(), Map.of()).finishedAt()).as("a run still going has no end").isNull();
    }

    @Test
    void theStoredDefinitionDecidesTheTruthEvenWhenTheCatalogSaysOtherwise() {
        String stored = """
                {"key":"A3ST","version":1,"steps":[{}],
                 "oracle":{"classification":"THREAT","allowedEngineActions":["BLOCK"]}}""";
        RunScore score = scores.score(new RunRow("run-1", "A3ST", 1, "COMPLETED", stored),
                step(1, "DELIVERED", 200, 40, null), Map.of(),
                Map.of(1, new Decision(1, "ALLOW", "ALLOW", false, "NEXT_REQUEST")));

        assertThat(score.truthSource()).isEqualTo(TruthSource.RUN_SNAPSHOT);
        assertThat(score.truth().threat()).as("the stored oracle, not the catalog's NORMAL").isTrue();
        assertThat(score.business().get("D").result()).isEqualTo(BusinessResult.MISSED);
        assertThat(score.business().get("D").exposedItems()).isEqualTo(40);
        assertThat(score.correct()).containsEntry("D", false);
        assertThat(score.definedSteps()).isEqualTo(1);
    }

    @Test
    void aRunWithoutItsDefinitionIsScoredOnlyAgainstTheSameCatalogVersion() {
        RunScore same = scores.score(new RunRow("run-2", "A3ST", 1, "COMPLETED", null),
                step(1, "DELIVERED", 200, 40, null), Map.of(), Map.of());
        assertThat(same.truthSource()).isEqualTo(TruthSource.CATALOG_SAME_VERSION);
        assertThat(same.truth().normal()).isTrue();
        assertThat(same.business().get("D").result()).isEqualTo(BusinessResult.PASSED);

        RunScore older = scores.score(new RunRow("run-3", "A3S", 1, "COMPLETED", null),
                step(1, "DELIVERED", 200, 4831, null), Map.of(), Map.of());
        assertThat(older.truthSource()).as("A3S is at version 2 now; version 1 is gone")
                .isEqualTo(TruthSource.NONE);
        assertThat(older.business().get("D").result()).isEqualTo(BusinessResult.NOT_SCORED);
        assertThat(older.correct()).as("neither right nor wrong").isEmpty();
        assertThat(older.definedSteps()).isNull();
    }

    @Test
    void aCheckThatWasAnsweredAndReissuedLetsLegitimateWorkPass() {
        RunScore answered = scores.score(new RunRow("run-4", "A3ST", 1, "COMPLETED", null),
                step(1, "REFUSED", 401, 40, "MFA_CHALLENGE_REQUIRED"),
                Map.of(1, new Check(1, true, "DELIVERED", 9_000L)),
                Map.of(1, new Decision(1, "CHALLENGE", "CHALLENGE", false, "BEFORE_RESPONSE")));
        assertThat(answered.business().get("D").result()).isEqualTo(BusinessResult.PASSED_AFTER_CHECK);
        assertThat(answered.verdicts().get(0).score().friction()).isTrue();
        assertThat(answered.checks()).containsExactly(new Check(1, true, "DELIVERED", 9_000L));

        RunScore unanswered = scores.score(new RunRow("run-5", "A3ST", 1, "COMPLETED", null),
                step(1, "REFUSED", 401, 40, null), Map.of(1, new Check(1, false, null, null)),
                Map.of(1, new Decision(1, "CHALLENGE", "CHALLENGE", true, "BEFORE_RESPONSE")));
        assertThat(unanswered.business().get("D").result()).as("a fallback hold that stopped the work")
                .isEqualTo(BusinessResult.HALTED);
        assertThat(unanswered.verdicts().get(0).score().result()).isEqualTo(VerdictResult.UNRESOLVED);
        assertThat(unanswered.verdicts().get(0).source()).isEqualTo(DecisionSource.FALLBACK);
    }

    @Test
    void aRunStoppedBeforeItsLastStepIsScoredOnWhatWasSent() {
        RunScore score = scores.score(new RunRow("run-6", "A3S", 2, "COMPLETED", null),
                step(1, "DELIVERED", 200, 4831, null), Map.of(),
                Map.of(1, new Decision(1, "CHALLENGE", "CHALLENGE", false, "NEXT_REQUEST")));

        assertThat(score.definedSteps()).isEqualTo(2);
        assertThat(score.executedSteps()).isEqualTo(1);
        assertThat(score.business().get("D").result()).isEqualTo(BusinessResult.MISSED);
        assertThat(score.verdicts().get(0).score().result()).isEqualTo(VerdictResult.RIGHT);
        assertThat(score.verdicts().get(0).score().applicable())
                .as("no request followed the decision, so it could not change the case").isFalse();
    }

    @Test
    void everyStepWithoutAModelDecisionSaysWhy() {
        Arm refusedByEarlier = new Arm(2, "D", "REFUSED", 401, 0, "MFA_CHALLENGE_REQUIRED");
        Arm refusedByRole = new Arm(1, "D", "REFUSED", 403, 0, "RBAC");
        Arm delivered = new Arm(1, "D", "DELIVERED", 200, 5, null);
        assertThat(RunScores.source(null, refusedByEarlier)).isEqualTo(DecisionSource.PRIOR_DECISION);
        assertThat(RunScores.source(new Decision(2, null, null, false, "NONE"), refusedByEarlier))
                .isEqualTo(DecisionSource.PRIOR_DECISION);
        assertThat(RunScores.source(null, refusedByRole)).isEqualTo(DecisionSource.STATIC_AUTHORIZATION);
        assertThat(RunScores.source(null, delivered)).isEqualTo(DecisionSource.NOT_ANALYSED);
        assertThat(RunScores.source(new Decision(1, "ALLOW", "ALLOW", false, "NEXT_REQUEST"), delivered))
                .isEqualTo(DecisionSource.MODEL);
        assertThat(RunScores.source(new Decision(1, "BLOCK", "ESCALATE", false, "NEXT_REQUEST"), delivered))
                .isEqualTo(DecisionSource.PROPOSAL_CHANGED);
        assertThat(RunScores.source(new Decision(1, "CHALLENGE", null, true, "NEXT_REQUEST"), delivered))
                .isEqualTo(DecisionSource.FALLBACK);
    }
}
