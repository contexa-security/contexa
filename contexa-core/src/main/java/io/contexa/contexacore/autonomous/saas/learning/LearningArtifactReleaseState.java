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
 * Common release lifecycle states for learning artifacts.
 */
public enum LearningArtifactReleaseState {
    COLLECTING(false, false),
    SHADOW_READY(false, false),
    REPLAY_READY(false, false),
    CANARY_READY(false, false),
    PROMOTED(true, false),
    REVIEW_ONLY(false, true),
    WITHDRAWN(false, false),
    KILL_SWITCH_ACTIVE(false, false);

    private final boolean runtimeEligible;
    private final boolean reviewState;

    LearningArtifactReleaseState(boolean runtimeEligible, boolean reviewState) {
        this.runtimeEligible = runtimeEligible;
        this.reviewState = reviewState;
    }

    public boolean isRuntimeEligible() {
        return runtimeEligible;
    }

    public boolean isReviewState() {
        return reviewState;
    }

    public boolean isTerminal() {
        return this == WITHDRAWN || this == KILL_SWITCH_ACTIVE;
    }
}
