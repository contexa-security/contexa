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

import java.util.List;
import java.util.Objects;

/**
 * Shared metadata envelope for learning artifacts.
 */
public record LearningArtifactMetadata(
        LearningArtifactReleaseState releaseState,
        LearningArtifactMetrics metrics,
        List<LearningArtifactGuardrail> guardrails) implements LearningArtifactLifecycle {

    public LearningArtifactMetadata {
        releaseState = Objects.requireNonNullElse(releaseState, LearningArtifactReleaseState.COLLECTING);
        metrics = metrics == null ? LearningArtifactMetrics.empty() : metrics;
        guardrails = guardrails == null ? List.of() : List.copyOf(guardrails);
    }

    public static LearningArtifactMetadata collecting() {
        return new LearningArtifactMetadata(
                LearningArtifactReleaseState.COLLECTING,
                LearningArtifactMetrics.empty(),
                List.of());
    }

    public boolean hasGuardrails() {
        return !guardrails.isEmpty();
    }

    public boolean hasBlockingGuardrails() {
        return guardrails.stream().anyMatch(LearningArtifactGuardrail::blocking);
    }

    public long blockingGuardrailCount() {
        return guardrails.stream().filter(LearningArtifactGuardrail::blocking).count();
    }
}
