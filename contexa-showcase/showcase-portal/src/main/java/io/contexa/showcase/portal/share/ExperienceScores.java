package io.contexa.showcase.portal.share;

import io.contexa.showcase.portal.replay.PairDefinition.SceneKind;
import io.contexa.showcase.portal.replay.ReplayGuard;
import io.contexa.showcase.portal.replay.ReplayView;
import io.contexa.showcase.portal.replay.ReplayViews;
import io.contexa.showcase.portal.share.ExperienceResult.SceneResult;
import io.contexa.showcase.portal.share.ExperienceResult.Score;
import io.contexa.showcase.portal.visitor.VisitorStore;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Scores a pair the visitor has seen. The right answer comes from the scene: an attack must not deliver the data, a
 * legitimate request must (an extra check by Contexa is allowed). Contexa is scored from the published recording at
 * the featured step, exactly what screen 1 shows. The visitor is scored from the stored votes; a legitimate scene
 * without its own vote takes the first question's call, because the two requests look the same (approval Q-35).
 */
public class ExperienceScores {

    private final ReplayViews replays;
    private final ReplayGuard guard;
    private final VisitorStore visitors;

    public ExperienceScores(ReplayViews replays, ReplayGuard guard, VisitorStore visitors) {
        this.replays = replays;
        this.guard = guard;
        this.visitors = visitors;
    }

    /** The result of a published, consistent pair; empty when the pair is not shown to visitors. */
    public Optional<ExperienceResult> score(String pairKey, String visitorHash) {
        Optional<ReplayView.Pair> pair = replays.published(pairKey)
                .filter(published -> published.scenes().stream().noneMatch(scene -> guard.blocked(scene.recordId())));
        if (pair.isEmpty()) {
            return Optional.empty();
        }
        Map<String, String> votes = visitorHash == null ? Map.of() : visitors.predictions(visitorHash);
        String firstCall = votes.get(pairKey + ":" + SceneKind.ATTACK.name());
        List<SceneResult> scenes = new ArrayList<>();
        int myHits = 0;
        int myTotal = 0;
        int contexaHits = 0;
        for (ReplayView.Scene scene : pair.get().scenes()) {
            String own = votes.get(pairKey + ":" + scene.kind());
            boolean carriedOver = own == null && firstCall != null
                    && SceneKind.LEGITIMATE.name().equals(scene.kind());
            String choice = own != null ? own : carriedOver ? firstCall : null;
            Boolean myCorrect = choice == null ? null : choiceIsRight(scene.kind(), choice);
            ReplayView.Layer contexa = scene.layers().stream().filter(layer -> "D".equals(layer.control()))
                    .findFirst().orElseThrow(() -> new IllegalStateException("Scene without control D"));
            boolean contexaCorrect = outcomeIsRight(scene.kind(), contexa.outcome(), contexa.verdict());
            scenes.add(new SceneResult(scene.kind(), choice, carriedOver, myCorrect, contexa.outcome(),
                    contexa.verdict(), contexaCorrect));
            if (myCorrect != null) {
                myTotal++;
                myHits += myCorrect ? 1 : 0;
            }
            contexaHits += contexaCorrect ? 1 : 0;
        }
        return Optional.of(new ExperienceResult(pairKey, scenes, myTotal == 0 ? null : new Score(myHits, myTotal),
                new Score(contexaHits, scenes.size())));
    }

    static boolean choiceIsRight(String kind, String choice) {
        return SceneKind.ATTACK.name().equals(kind) ? "BLOCK".equals(choice) : "ALLOW".equals(choice);
    }

    /**
     * An attack is stopped when the data did not leave (refused, held for a check or review, or cut mid-response); a
     * legitimate request passes when the data was delivered or Contexa asked for an extra check. Unresolved is never
     * right.
     */
    static boolean outcomeIsRight(String kind, String outcome, String verdict) {
        if (SceneKind.ATTACK.name().equals(kind)) {
            return "STOPPED".equals(outcome) || "HELD".equals(outcome) || "CUT".equals(outcome);
        }
        return "DELIVERED".equals(outcome) || ("HELD".equals(outcome) && "CHALLENGE".equals(verdict));
    }
}
