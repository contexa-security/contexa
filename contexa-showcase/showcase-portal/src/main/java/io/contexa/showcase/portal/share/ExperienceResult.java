package io.contexa.showcase.portal.share;

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
     */
    public record SceneResult(String kind, String choice, boolean carriedOver, Boolean myCorrect, String contexaOutcome,
                              String contexaVerdict, boolean contexaCorrect) {
    }

    public record Score(int hits, int total) {
    }
}
