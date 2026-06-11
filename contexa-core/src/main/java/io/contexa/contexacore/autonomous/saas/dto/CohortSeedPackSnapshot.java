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
package io.contexa.contexacore.autonomous.saas.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.LocalDateTime;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record CohortSeedPackSnapshot(
        String tenantId,
        boolean featureEnabled,
        boolean sharingEnabled,
        boolean seedAvailable,
        boolean seedQualified,
        String cohortKey,
        String industryCategory,
        String region,
        String sizeBand,
        int cohortTenantCount,
        long sampleUserBaselineCount,
        String supportLevel,
        String promotionState,
        long earlyAssessmentSampleCount,
        double earlyQualityImprovementDelta,
        List<Integer> topAccessHours,
        List<Integer> topAccessDays,
        List<String> topOperatingSystems,
        List<DistributionItem> firstSequenceFamilies,
        List<DistributionItem> sessionLengthBands,
        List<DistributionItem> surfaceTransitionPriors,
        List<String> evidenceFacts,
        LocalDateTime generatedAt) {

    public CohortSeedPackSnapshot {
        topAccessHours = topAccessHours == null ? List.of() : List.copyOf(topAccessHours);
        topAccessDays = topAccessDays == null ? List.of() : List.copyOf(topAccessDays);
        topOperatingSystems = topOperatingSystems == null ? List.of() : List.copyOf(topOperatingSystems);
        firstSequenceFamilies = firstSequenceFamilies == null ? List.of() : List.copyOf(firstSequenceFamilies);
        sessionLengthBands = sessionLengthBands == null ? List.of() : List.copyOf(sessionLengthBands);
        surfaceTransitionPriors = surfaceTransitionPriors == null ? List.of() : List.copyOf(surfaceTransitionPriors);
        evidenceFacts = evidenceFacts == null ? List.of() : List.copyOf(evidenceFacts);
    }

    public static CohortSeedPackSnapshot empty() {
        return new CohortSeedPackSnapshot(null, false, false, false, false, null, null, null, null, 0, 0L, "INSUFFICIENT", "DISABLED", 0L, 0.0d, List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), null);
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record DistributionItem(String key, long count) {
    }
}