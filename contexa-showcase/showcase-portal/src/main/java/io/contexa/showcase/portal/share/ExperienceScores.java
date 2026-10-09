package io.contexa.showcase.portal.share;

import io.contexa.showcase.portal.replay.PairDefinition.SceneKind;
import io.contexa.showcase.portal.replay.ReplayGuard;
import io.contexa.showcase.portal.replay.ReplayView;
import io.contexa.showcase.portal.replay.ReplayViews;
import io.contexa.showcase.portal.scoring.RunScores;
import io.contexa.showcase.portal.scoring.Scoring;
import io.contexa.showcase.portal.scoring.Scoring.CaseScore;
import io.contexa.showcase.portal.share.ExperienceResult.SceneResult;
import io.contexa.showcase.portal.share.ExperienceResult.Score;
import io.contexa.showcase.portal.visitor.VisitorStore;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Scores a pair the visitor has seen. Contexa is scored by the one scoring rule ({@link RunScores},
 * docs/showcase/데모-재설계.md 5.0) on the published recording's representative run: control D's business result over
 * the whole case against the ground truth of the definition the run executed. A partial stop, an unresolved case or a
 * case without a ground truth is shown by its result and counted neither right nor wrong. The visitor is scored from
 * the stored votes; a legitimate scene without its own vote takes the first question's call, because the two requests
 * look the same (approval Q-35).
 */
public class ExperienceScores {

    private final ReplayViews replays;
    private final ReplayGuard guard;
    private final VisitorStore visitors;
    private final RunScores scores;

    public ExperienceScores(ReplayViews replays, ReplayGuard guard, VisitorStore visitors, RunScores scores) {
        this.replays = replays;
        this.guard = guard;
        this.visitors = visitors;
        this.scores = scores;
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
        int contexaTotal = 0;
        for (ReplayView.Scene scene : pair.get().scenes()) {
            String own = votes.get(pairKey + ":" + scene.kind());
            boolean carriedOver = own == null && firstCall != null
                    && SceneKind.LEGITIMATE.name().equals(scene.kind());
            String choice = own != null ? own : carriedOver ? firstCall : null;
            Boolean myCorrect = choice == null ? null : choiceIsRight(scene.kind(), choice);
            ReplayView.Layer contexa = scene.layers().stream().filter(layer -> "D".equals(layer.control()))
                    .findFirst().orElseThrow(() -> new IllegalStateException("Scene without control D"));
            RunScores.RunScore run = scores.score(scene.runId())
                    .orElseThrow(() -> new IllegalStateException("Recording without its run: " + scene.runId()));
            CaseScore score = run.business().get("D");
            Long resumed = run.checks().stream()
                    .filter(check -> check.answered() && "DELIVERED".equals(check.reissueOutcome())
                            && check.releaseMillis() != null)
                    .map(RunScores.Check::releaseMillis).findFirst().orElse(null);
            Boolean contexaCorrect = Scoring.correct(score.result());
            scenes.add(new SceneResult(scene.kind(), choice, carriedOver, myCorrect, contexa.outcome(),
                    contexa.verdict(), score.result().name(), score.exposedItems(), contexaCorrect, scene.truth(),
                    run.scenarioKey(), resumed));
            if (myCorrect != null) {
                myTotal++;
                myHits += myCorrect ? 1 : 0;
            }
            if (contexaCorrect != null) {
                contexaTotal++;
                contexaHits += contexaCorrect ? 1 : 0;
            }
        }
        return Optional.of(new ExperienceResult(pairKey, scenes, myTotal == 0 ? null : new Score(myHits, myTotal),
                new Score(contexaHits, contexaTotal)));
    }

    /** The question of a pair per language, the share card's title (H-09 #30); empty for an unknown pair. */
    public Optional<Map<String, String>> question(String pairKey) {
        return replays.question(pairKey);
    }

    static boolean choiceIsRight(String kind, String choice) {
        return SceneKind.ATTACK.name().equals(kind) ? "BLOCK".equals(choice) : "ALLOW".equals(choice);
    }

}
