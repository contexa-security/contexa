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
package io.contexa.contexacore.autonomous.saas.learning.cohort;

import io.contexa.contexacore.autonomous.saas.dto.BaselineSeedSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Default cohort seed qualification policy based on cohort support, sample size, and early quality improvement.
 */
public class DefaultCohortSeedQualificationService implements CohortSeedQualificationService {

    private final CohortSeedQualificationThresholds thresholds;

    public DefaultCohortSeedQualificationService() {
        this(CohortSeedQualificationThresholds.defaults());
    }

    public DefaultCohortSeedQualificationService(CohortSeedQualificationThresholds thresholds) {
        this.thresholds = Objects.requireNonNull(thresholds, "thresholds is required");
    }

    @Override
    public CohortSeedQualificationDecision qualify(CohortSeedQualificationInput input) {
        CohortSeedQualificationInput safeInput = input == null
                ? new CohortSeedQualificationInput(null, 0L, 0.0d)
                : input;
        BaselineSeedSnapshot snapshot = safeInput.baselineSeedSnapshot();
        int cohortTenantCount = snapshot != null ? Math.max(snapshot.cohortTenantCount(), 0) : 0;
        long sampleUserBaselineCount = snapshot != null ? Math.max(snapshot.sampleUserBaselineCount(), 0L) : 0L;
        boolean seedAvailable = snapshot != null && snapshot.seedAvailable();

        List<String> blockingReasons = new ArrayList<>();
        if (!seedAvailable) {
            blockingReasons.add("Baseline seed snapshot is unavailable or not marked seedAvailable.");
        }
        if (cohortTenantCount < thresholds.minimumCohortTenantCount()) {
            blockingReasons.add(String.format(Locale.ROOT,
                    "Cohort tenant count %d is below the minimum cohort support floor %d.",
                    cohortTenantCount,
                    thresholds.minimumCohortTenantCount()));
        }
        if (sampleUserBaselineCount < thresholds.minimumSampleUserBaselineCount()) {
            blockingReasons.add(String.format(Locale.ROOT,
                    "Sample user baseline count %d is below the minimum seed sample floor %d.",
                    sampleUserBaselineCount,
                    thresholds.minimumSampleUserBaselineCount()));
        }
        if (safeInput.earlyAssessmentSampleCount() < thresholds.minimumEarlyAssessmentSampleCount()) {
            blockingReasons.add(String.format(Locale.ROOT,
                    "Early assessment sample count %d is below the minimum early-signal floor %d.",
                    safeInput.earlyAssessmentSampleCount(),
                    thresholds.minimumEarlyAssessmentSampleCount()));
        }
        if (safeInput.earlyQualityImprovementDelta() < thresholds.minimumEarlyQualityImprovementDelta()) {
            blockingReasons.add(String.format(Locale.ROOT,
                    "Early quality improvement delta %.1f is below the minimum cold-start improvement floor %.1f.",
                    safeInput.earlyQualityImprovementDelta(),
                    thresholds.minimumEarlyQualityImprovementDelta()));
        }

        boolean qualified = blockingReasons.isEmpty();
        CohortSeedSupportLevel supportLevel = resolveSupportLevel(seedAvailable, cohortTenantCount, sampleUserBaselineCount, safeInput.earlyQualityImprovementDelta());
        LearningArtifactReleaseState releaseState = qualified ? LearningArtifactReleaseState.SHADOW_READY : LearningArtifactReleaseState.COLLECTING;
        return new CohortSeedQualificationDecision(
                qualified,
                supportLevel,
                releaseState,
                List.copyOf(blockingReasons),
                List.of(
                        String.format(Locale.ROOT,
                                "Cohort support tenants=%d, sampled baselines=%d, seedAvailable=%s.",
                                cohortTenantCount,
                                sampleUserBaselineCount,
                                seedAvailable),
                        String.format(Locale.ROOT,
                                "Early cold-start evidence sample=%d, improvementDelta=%.1f.",
                                safeInput.earlyAssessmentSampleCount(),
                                safeInput.earlyQualityImprovementDelta()),
                        String.format(Locale.ROOT,
                                "Qualification thresholds: cohort>=%d, sampledBaselines>=%d, earlySample>=%d, improvementDelta>=%.1f.",
                                thresholds.minimumCohortTenantCount(),
                                thresholds.minimumSampleUserBaselineCount(),
                                thresholds.minimumEarlyAssessmentSampleCount(),
                                thresholds.minimumEarlyQualityImprovementDelta())));
    }

    private CohortSeedSupportLevel resolveSupportLevel(
            boolean seedAvailable,
            int cohortTenantCount,
            long sampleUserBaselineCount,
            double earlyQualityImprovementDelta) {
        if (!seedAvailable) {
            return CohortSeedSupportLevel.INSUFFICIENT;
        }
        if (cohortTenantCount >= thresholds.strongCohortTenantCount()
                && sampleUserBaselineCount >= thresholds.strongSampleUserBaselineCount()
                && earlyQualityImprovementDelta >= thresholds.strongEarlyQualityImprovementDelta()) {
            return CohortSeedSupportLevel.STRONG;
        }
        if (cohortTenantCount >= thresholds.minimumCohortTenantCount()
                && sampleUserBaselineCount >= thresholds.minimumSampleUserBaselineCount()
                && earlyQualityImprovementDelta >= thresholds.minimumEarlyQualityImprovementDelta()) {
            return CohortSeedSupportLevel.SUPPORTED;
        }
        return CohortSeedSupportLevel.INSUFFICIENT;
    }
}