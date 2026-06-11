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
import io.contexa.contexacore.autonomous.saas.dto.CohortSeedPackSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactTypeNames;
import io.contexa.contexacore.autonomous.saas.learning.release.LearningArtifactReleaseLedgerService;
import java.util.List;
final class CohortSeedRoiScorer extends AbstractLearningRoiArtifactScorer {
    CohortSeedRoiScorer(LearningArtifactReleaseLedgerService ledgerService) {
        super(LearningArtifactTypeNames.COHORT_SEED, ledgerService);
    }
    @Override
    public List<LearningRoiArtifactScore> score(LearningRoiScoreboardInput input) {
        CohortSeedPackSnapshot snapshot = input == null ? null : input.cohortSeedPack();
        if (snapshot == null || !snapshot.seedAvailable() || !snapshot.seedQualified()) {
            return List.of();
        }
        return List.of(scoreArtifact(
                snapshot.cohortKey(),
                snapshot.promotionState(),
                snapshot.sampleUserBaselineCount(),
                snapshot.earlyQualityImprovementDelta(),
                0.0d,
                input.costModel()));
    }
}
