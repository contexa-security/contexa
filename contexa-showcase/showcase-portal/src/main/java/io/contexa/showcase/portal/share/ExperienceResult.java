package io.contexa.showcase.portal.share;

import io.contexa.showcase.portal.replay.ReplayView;

import java.util.List;

/**
 * The visitor's result of a pair (deck p.15, docs/showcase/P5-설계.md section 4): each scene's right answer, the
 * visitor's call and what Contexa did, scored once on the server so the end screen and the share card agree.
 *
 * @param mine null when the visitor did not vote
 */
public record ExperienceResult(String pairKey, List<SceneResult> scenes, Score mine, Score contexa) {

    /**
     * @param choice         the visitor's call for the scene (ALLOW or BLOCK), or null
     * @param carriedOver    the call is the first question's, carried over to this look-alike scene (approval Q-35)
     * @param myCorrect      null without a call
     * @param contexaOutcome the business outcome of control D at the scene's featured step
     * @param contexaResult  control D's business result over the whole case by the one scoring rule
     *                       (docs/showcase/데모-재설계.md 5.0): STOPPED, PARTLY_STOPPED, MISSED, PASSED,
     *                       PASSED_AFTER_CHECK, HALTED, UNRESOLVED or NOT_SCORED
     * @param contexaExposed items that left over the whole case
     * @param contexaCorrect true for STOPPED, PASSED and PASSED_AFTER_CHECK, false for MISSED and HALTED, null for a
     *                       partial stop, an unresolved case or a case without a ground truth (shown by its result)
     * @param truth          the ground truth of the scene's run as recorded (F-13), the one the score is made against
     * @param scenarioKey    the case the scene's run executed, so a screen can compare the two cases' conditions
     * @param resumedMillis  from the additional check to the work going through again, when the run recorded that;
     *                       null otherwise (H-09 #29: the recovery is claimed only where it was recorded)
     */
    public record SceneResult(String kind, String choice, boolean carriedOver, Boolean myCorrect, String contexaOutcome,
                              String contexaVerdict, String contexaResult, long contexaExposed,
                              Boolean contexaCorrect, ReplayView.Truth truth, String scenarioKey,
                              Long resumedMillis) {
    }

    /** @param total the scenes counted: those with a right or wrong result */
    public record Score(int hits, int total) {
    }
}
