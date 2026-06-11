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
package io.contexa.contexacore.autonomous.saas.learning;

/**
 * Common lifecycle contract for learning artifacts.
 */
public interface LearningArtifactLifecycle {

    LearningArtifactReleaseState releaseState();

    default boolean isCollecting() {
        return releaseState() == LearningArtifactReleaseState.COLLECTING;
    }

    default boolean isShadowReady() {
        return releaseState() == LearningArtifactReleaseState.SHADOW_READY;
    }

    default boolean isReplayReady() {
        return releaseState() == LearningArtifactReleaseState.REPLAY_READY;
    }

    default boolean isCanaryReady() {
        return releaseState() == LearningArtifactReleaseState.CANARY_READY;
    }

    default boolean isPromoted() {
        return releaseState() == LearningArtifactReleaseState.PROMOTED;
    }

    default boolean isReviewOnly() {
        return releaseState() == LearningArtifactReleaseState.REVIEW_ONLY;
    }

    default boolean isWithdrawn() {
        return releaseState() == LearningArtifactReleaseState.WITHDRAWN;
    }

    default boolean isKillSwitchActive() {
        return releaseState() == LearningArtifactReleaseState.KILL_SWITCH_ACTIVE;
    }

    default boolean isRuntimeEligible() {
        return releaseState().isRuntimeEligible();
    }
}
