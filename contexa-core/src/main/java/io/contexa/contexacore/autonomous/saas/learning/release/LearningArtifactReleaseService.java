package io.contexa.contexacore.autonomous.saas.learning.release;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetadata;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import org.springframework.stereotype.Service;

import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Enforces the shared release lifecycle for learning artifacts.
 */
@Service
public class LearningArtifactReleaseService {

    private static final Map<LearningArtifactReleaseState, EnumSet<LearningArtifactReleaseState>> ALLOWED_TARGETS = createAllowedTargets();

    public LearningArtifactMetadata transition(LearningArtifactMetadata metadata, LearningArtifactReleaseState targetState) {
        LearningArtifactMetadata current = metadata == null ? LearningArtifactMetadata.collecting() : metadata;
        LearningArtifactReleaseTransition transition = preview(current.releaseState(), targetState);
        if (!transition.allowed()) {
            throw new IllegalStateException(
                    "Learning artifact release transition is not allowed from "
                            + transition.currentState()
                            + " to "
                            + transition.targetState());
        }
        if (transition.noOp()) {
            return current;
        }
        return new LearningArtifactMetadata(transition.targetState(), current.metrics(), current.guardrails());
    }

    public LearningArtifactReleaseTransition preview(LearningArtifactReleaseState currentState, LearningArtifactReleaseState targetState) {
        LearningArtifactReleaseState safeCurrent = Objects.requireNonNullElse(currentState, LearningArtifactReleaseState.COLLECTING);
        LearningArtifactReleaseState safeTarget = Objects.requireNonNull(targetState, "targetState is required");
        List<LearningArtifactReleaseState> allowedTargets = allowedTargets(safeCurrent);
        boolean noOp = safeCurrent == safeTarget;
        boolean allowed = noOp || allowedTargets.contains(safeTarget);
        return new LearningArtifactReleaseTransition(
                safeCurrent,
                safeTarget,
                allowed,
                noOp,
                safeCurrent.isRuntimeEligible(),
                safeTarget.isRuntimeEligible(),
                allowedTargets);
    }

    public List<LearningArtifactReleaseState> allowedTargets(LearningArtifactReleaseState currentState) {
        LearningArtifactReleaseState safeCurrent = Objects.requireNonNullElse(currentState, LearningArtifactReleaseState.COLLECTING);
        EnumSet<LearningArtifactReleaseState> allowed = ALLOWED_TARGETS.getOrDefault(safeCurrent, EnumSet.noneOf(LearningArtifactReleaseState.class));
        return List.copyOf(allowed);
    }

    private static Map<LearningArtifactReleaseState, EnumSet<LearningArtifactReleaseState>> createAllowedTargets() {
        Map<LearningArtifactReleaseState, EnumSet<LearningArtifactReleaseState>> transitions = new EnumMap<>(LearningArtifactReleaseState.class);
        transitions.put(LearningArtifactReleaseState.COLLECTING, EnumSet.of(
                LearningArtifactReleaseState.SHADOW_READY,
                LearningArtifactReleaseState.REVIEW_ONLY,
                LearningArtifactReleaseState.WITHDRAWN,
                LearningArtifactReleaseState.KILL_SWITCH_ACTIVE));
        transitions.put(LearningArtifactReleaseState.SHADOW_READY, EnumSet.of(
                LearningArtifactReleaseState.REPLAY_READY,
                LearningArtifactReleaseState.REVIEW_ONLY,
                LearningArtifactReleaseState.WITHDRAWN,
                LearningArtifactReleaseState.KILL_SWITCH_ACTIVE));
        transitions.put(LearningArtifactReleaseState.REPLAY_READY, EnumSet.of(
                LearningArtifactReleaseState.CANARY_READY,
                LearningArtifactReleaseState.REVIEW_ONLY,
                LearningArtifactReleaseState.WITHDRAWN,
                LearningArtifactReleaseState.KILL_SWITCH_ACTIVE));
        transitions.put(LearningArtifactReleaseState.CANARY_READY, EnumSet.of(
                LearningArtifactReleaseState.PROMOTED,
                LearningArtifactReleaseState.REVIEW_ONLY,
                LearningArtifactReleaseState.WITHDRAWN,
                LearningArtifactReleaseState.KILL_SWITCH_ACTIVE));
        transitions.put(LearningArtifactReleaseState.PROMOTED, EnumSet.of(
                LearningArtifactReleaseState.REVIEW_ONLY,
                LearningArtifactReleaseState.WITHDRAWN,
                LearningArtifactReleaseState.KILL_SWITCH_ACTIVE));
        transitions.put(LearningArtifactReleaseState.REVIEW_ONLY, EnumSet.of(
                LearningArtifactReleaseState.SHADOW_READY,
                LearningArtifactReleaseState.REPLAY_READY,
                LearningArtifactReleaseState.CANARY_READY,
                LearningArtifactReleaseState.WITHDRAWN,
                LearningArtifactReleaseState.KILL_SWITCH_ACTIVE));
        transitions.put(LearningArtifactReleaseState.WITHDRAWN, EnumSet.noneOf(LearningArtifactReleaseState.class));
        transitions.put(LearningArtifactReleaseState.KILL_SWITCH_ACTIVE, EnumSet.noneOf(LearningArtifactReleaseState.class));
        return Map.copyOf(transitions);
    }
}
