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
package io.contexa.contexacore.autonomous.saas.learning.quality;

import io.contexa.contexacore.autonomous.saas.dto.DecisionQualityProfileSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactGuardrail;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactLifecycle;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetadata;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;

/**
 * Assembles decision-quality-learning telemetry into transport snapshots.
 */
public class DecisionQualityProfileSnapshotAssembler {

    private static final String DEFAULT_VERSION = "1.0.0";

    public DecisionQualityProfileSnapshot assembleSnapshot(
            String tenantId,
            boolean featureEnabled,
            boolean sharingEnabled,
            List<DecisionQualityProfileCandidate> candidates) {
        List<DecisionQualityProfileCandidate> safeCandidates = candidates == null ? List.of() : List.copyOf(candidates);
        if (safeCandidates.isEmpty()) {
            return DecisionQualityProfileSnapshot.empty();
        }

        List<DecisionQualityProfileSnapshot.ProfileItem> items = safeCandidates.stream()
                .map(this::toSnapshotItem)
                .toList();

        return new DecisionQualityProfileSnapshot(
                tenantId,
                featureEnabled,
                sharingEnabled,
                safeCandidates.stream().anyMatch(candidate -> candidate.metadata().isRuntimeEligible()),
                summarizePromotionState(safeCandidates),
                safeCandidates.stream().filter(candidate -> candidate.metadata().isPromoted()).count(),
                safeCandidates.stream().filter(candidate -> !candidate.metadata().isCollecting()).count(),
                safeCandidates.stream().filter(candidate -> candidate.metadata().isCollecting()).count(),
                items,
                LocalDateTime.now());
    }

    private DecisionQualityProfileSnapshot.ProfileItem toSnapshotItem(DecisionQualityProfileCandidate candidate) {
        DecisionQualityScenarioResult result = candidate.scenarioResult();
        DecisionBiasAggregationResult aggregation = result.biasAggregation();
        LearningArtifactMetadata metadata = candidate.metadata();
        return new DecisionQualityProfileSnapshot.ProfileItem(
                profileKey(result.scenarioClass()),
                DEFAULT_VERSION,
                result.scenarioClass(),
                aggregation.sampleSize(),
                aggregation.operatorReviewedOutcomeCount(),
                aggregation.falsePositiveRate(),
                aggregation.falseNegativeRate(),
                aggregation.challengeOverfireRate(),
                aggregation.allowUnderfireRate(),
                metadata.isRuntimeEligible(),
                metadata.releaseState().name(),
                metadata.guardrails().stream().map(LearningArtifactGuardrail::summary).toList(),
                result.evidenceFacts(),
                candidate.policyFacts());
    }

    private String summarizePromotionState(List<DecisionQualityProfileCandidate> candidates) {
        return candidates.stream()
                .map(DecisionQualityProfileCandidate::metadata)
                .map(LearningArtifactLifecycle::releaseState)
                .min(this::statePriority)
                .orElse(LearningArtifactReleaseState.COLLECTING)
                .name();
    }

    private int statePriority(LearningArtifactReleaseState left, LearningArtifactReleaseState right) {
        return Integer.compare(priority(left), priority(right));
    }

    private int priority(LearningArtifactReleaseState state) {
        if (state == null) {
            return Integer.MAX_VALUE;
        }
        return switch (state) {
            case PROMOTED -> 0;
            case CANARY_READY -> 1;
            case REPLAY_READY -> 2;
            case SHADOW_READY -> 3;
            case REVIEW_ONLY -> 4;
            case COLLECTING -> 5;
            case WITHDRAWN -> 6;
            case KILL_SWITCH_ACTIVE -> 7;
        };
    }

    private String profileKey(String scenarioClass) {
        if (scenarioClass == null || scenarioClass.isBlank()) {
            return "decision-quality-profile/unclassified";
        }
        return "decision-quality-profile/" + scenarioClass.trim().toLowerCase(Locale.ROOT).replace('_', '-');
    }
}
