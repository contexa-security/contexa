/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.autonomous.saas.learning.roi;
import io.contexa.contexacore.autonomous.saas.learning.release.LearningArtifactReleaseLedgerService;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
/**
 * Computes ROI scoreboard across promoted learning artifacts.
 */
public class LearningRoiScoreboardService {
    private final List<LearningRoiArtifactScorer> scorers;
    public LearningRoiScoreboardService(LearningArtifactReleaseLedgerService ledgerService) {
        this.scorers = List.of(
                new DetectionStrategyRoiScorer(ledgerService),
                new DecisionQualityRoiScorer(ledgerService),
                new PromptPresentationRoiScorer(ledgerService),
                new CohortSeedRoiScorer(ledgerService));
    }
    public LearningRoiScoreboard score(LearningRoiScoreboardInput input) {
        LearningRoiScoreboardInput normalized = input == null ? LearningRoiScoreboardInput.empty() : input;
        List<LearningRoiArtifactScore> scores = new ArrayList<>();
        for (LearningRoiArtifactScorer scorer : scorers) {
            scores.addAll(scorer.score(normalized));
        }
        scores.sort(Comparator.comparingDouble(LearningRoiArtifactScore::netScore).reversed());
        double totalOperatingCost = scores.stream().mapToDouble(LearningRoiArtifactScore::operatingCost).sum();
        double totalDetectionLiftValue = scores.stream().mapToDouble(LearningRoiArtifactScore::detectionLiftValue).sum();
        double totalFalsePositiveCost = scores.stream().mapToDouble(LearningRoiArtifactScore::falsePositiveCost).sum();
        double totalRollbackPenalty = scores.stream().mapToDouble(LearningRoiArtifactScore::rollbackPenalty).sum();
        double totalNetScore = scores.stream().mapToDouble(LearningRoiArtifactScore::netScore).sum();
        return new LearningRoiScoreboard(
                scores,
                totalOperatingCost,
                totalDetectionLiftValue,
                totalFalsePositiveCost,
                totalRollbackPenalty,
                totalNetScore,
                LocalDateTime.now());
    }
}
