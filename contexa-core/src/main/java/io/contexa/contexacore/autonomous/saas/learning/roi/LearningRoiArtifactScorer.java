package io.contexa.contexacore.autonomous.saas.learning.roi;
import java.util.List;
interface LearningRoiArtifactScorer {
    List<LearningRoiArtifactScore> score(LearningRoiScoreboardInput input);
}
