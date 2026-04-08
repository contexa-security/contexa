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
