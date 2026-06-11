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

import java.util.Map;

/**
 * Input for cohort seed expansion.
 */
public record CohortSeedExpansionInput(
        BaselineSeedSnapshot baselineSeedSnapshot,
        CohortSeedQualificationDecision qualificationDecision,
        String sizeBand,
        long earlyAssessmentSampleCount,
        double earlyQualityImprovementDelta,
        Map<String, Long> firstSequenceFamilyDistribution,
        Map<String, Long> sessionLengthBandDistribution,
        Map<String, Long> surfaceTransitionPriorDistribution) {

    public CohortSeedExpansionInput {
        qualificationDecision = qualificationDecision == null
                ? new CohortSeedQualificationDecision(false, CohortSeedSupportLevel.INSUFFICIENT, null, java.util.List.of(), java.util.List.of())
                : qualificationDecision;
        sizeBand = normalize(sizeBand);
        earlyAssessmentSampleCount = Math.max(earlyAssessmentSampleCount, 0L);
        earlyQualityImprovementDelta = Double.isFinite(earlyQualityImprovementDelta) ? earlyQualityImprovementDelta : 0.0d;
        firstSequenceFamilyDistribution = firstSequenceFamilyDistribution == null ? Map.of() : Map.copyOf(firstSequenceFamilyDistribution);
        sessionLengthBandDistribution = sessionLengthBandDistribution == null ? Map.of() : Map.copyOf(sessionLengthBandDistribution);
        surfaceTransitionPriorDistribution = surfaceTransitionPriorDistribution == null ? Map.of() : Map.copyOf(surfaceTransitionPriorDistribution);
    }

    private static String normalize(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}