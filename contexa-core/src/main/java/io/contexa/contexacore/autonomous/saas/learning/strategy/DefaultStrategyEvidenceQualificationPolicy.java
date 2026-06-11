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
package io.contexa.contexacore.autonomous.saas.learning.strategy;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetrics;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Default qualification policy for strategy-learning artifact promotion.
 */
public class DefaultStrategyEvidenceQualificationPolicy implements StrategyEvidenceQualificationPolicy {

    private final StrategyEvidenceQualificationThresholds thresholds;

    public DefaultStrategyEvidenceQualificationPolicy(StrategyEvidenceQualificationThresholds thresholds) {
        this.thresholds = Objects.requireNonNull(thresholds, "thresholds is required");
    }

    @Override
    public StrategyEvidenceQualificationDecision evaluate(DetectionStrategyLearningFamilyResult familyResult) {
        if (familyResult == null) {
            return new StrategyEvidenceQualificationDecision(
                    false,
                    LearningArtifactReleaseState.COLLECTING,
                    List.of("Strategy family result is required."),
                    List.of("Qualification skipped because no strategy-family result was provided."));
        }

        LearningArtifactMetrics metrics = familyResult.metrics() == null
                ? LearningArtifactMetrics.empty()
                : familyResult.metrics();

        List<String> blockingReasons = new ArrayList<>();
        List<String> policyFacts = new ArrayList<>();

        policyFacts.add(String.format(Locale.ROOT,
                "Family=%s, outcomeEvidence=%d/%d, outcomeCoverage=%.4f, hardNegativeCoverage=%.4f, localLift=%.4f.",
                familyResult.strategyFamily(),
                familyResult.outcomeEvidenceCount(),
                metrics.sampleSize(),
                metrics.outcomeCoverageRate(),
                metrics.hardNegativeCoverage(),
                metrics.localLiftRate()));
        policyFacts.add(String.format(Locale.ROOT,
                "Thresholds: minimumEvidence=%d, minimumOutcomeCoverage=%.4f, minimumHardNegativeCoverage=%.4f, minimumLocalLift=%.4f.",
                thresholds.minimumEvidenceCount(),
                thresholds.minimumOutcomeCoverageRate(),
                thresholds.minimumHardNegativeCoverageRate(),
                thresholds.minimumLocalLiftRate()));

        if (familyResult.outcomeEvidenceCount() < thresholds.minimumEvidenceCount()) {
            blockingReasons.add(String.format(Locale.ROOT,
                    "Outcome evidence count %d is below the minimum evidence floor %d.",
                    familyResult.outcomeEvidenceCount(),
                    thresholds.minimumEvidenceCount()));
        }
        if (metrics.outcomeCoverageRate() < thresholds.minimumOutcomeCoverageRate()) {
            blockingReasons.add(String.format(Locale.ROOT,
                    "Outcome coverage %.4f is below the minimum outcome coverage floor %.4f.",
                    metrics.outcomeCoverageRate(),
                    thresholds.minimumOutcomeCoverageRate()));
        }
        if (metrics.hardNegativeCoverage() < thresholds.minimumHardNegativeCoverageRate()) {
            blockingReasons.add(String.format(Locale.ROOT,
                    "Hard-negative coverage %.4f is below the minimum hard-negative coverage floor %.4f.",
                    metrics.hardNegativeCoverage(),
                    thresholds.minimumHardNegativeCoverageRate()));
        }
        if (metrics.localLiftRate() < thresholds.minimumLocalLiftRate()) {
            blockingReasons.add(String.format(Locale.ROOT,
                    "Local lift %.4f is below the minimum local lift floor %.4f.",
                    metrics.localLiftRate(),
                    thresholds.minimumLocalLiftRate()));
        }

        boolean qualified = blockingReasons.isEmpty();
        policyFacts.add(qualified
                ? "Qualification passed. The strategy family can advance to artifact assembly as SHADOW_READY."
                : "Qualification failed. The strategy family must remain in COLLECTING until all evidence floors are met.");

        return new StrategyEvidenceQualificationDecision(
                qualified,
                qualified ? LearningArtifactReleaseState.SHADOW_READY : LearningArtifactReleaseState.COLLECTING,
                blockingReasons,
                policyFacts);
    }
}
