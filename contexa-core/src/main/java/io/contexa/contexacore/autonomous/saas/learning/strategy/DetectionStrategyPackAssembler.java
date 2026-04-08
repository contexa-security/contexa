package io.contexa.contexacore.autonomous.saas.learning.strategy;

import io.contexa.contexacore.autonomous.saas.dto.DetectionStrategyPackSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactGuardrail;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactLifecycle;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetadata;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactMetrics;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Assembles strategy-learning results into a transport snapshot and an internal runtime DTO.
 */
public class DetectionStrategyPackAssembler {

    private static final String DEFAULT_VERSION = "1.0.0";

    private static final Map<String, StrategyProfile> PROFILES = buildProfiles();

    public DetectionStrategyPackSnapshot assembleSnapshot(
            String tenantId,
            boolean featureEnabled,
            boolean sharingEnabled,
            List<DetectionStrategyPackCandidate> candidates) {
        List<DetectionStrategyPackCandidate> safeCandidates = candidates == null ? List.of() : List.copyOf(candidates);
        if (safeCandidates.isEmpty()) {
            return DetectionStrategyPackSnapshot.empty();
        }

        List<DetectionStrategyPackSnapshot.StrategyItem> items = safeCandidates.stream()
                .map(this::toSnapshotItem)
                .toList();

        return new DetectionStrategyPackSnapshot(
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

    public DetectionStrategyRuntimePack assembleRuntimePack(String tenantId, List<DetectionStrategyPackCandidate> candidates) {
        List<DetectionStrategyPackCandidate> safeCandidates = candidates == null ? List.of() : List.copyOf(candidates);
        if (safeCandidates.isEmpty()) {
            return DetectionStrategyRuntimePack.empty();
        }
        List<DetectionStrategyRuntimePack.RuntimeStrategyItem> items = safeCandidates.stream()
                .map(this::toRuntimeItem)
                .toList();
        return new DetectionStrategyRuntimePack(
                tenantId,
                safeCandidates.stream().anyMatch(candidate -> candidate.metadata().isRuntimeEligible()),
                items,
                LocalDateTime.now());
    }

    private DetectionStrategyPackSnapshot.StrategyItem toSnapshotItem(DetectionStrategyPackCandidate candidate) {
        StrategyProfile profile = profile(candidate.familyResult().strategyFamily());
        LearningArtifactMetadata metadata = candidate.metadata();
        LearningArtifactMetrics metrics = metadata.metrics();
        return new DetectionStrategyPackSnapshot.StrategyItem(
                strategyKey(candidate.familyResult().strategyFamily()),
                DEFAULT_VERSION,
                candidate.familyResult().strategyFamily(),
                profile.supportedThreatGoals(),
                profile.requiredSignals(),
                profile.recommendedSignals(),
                profile.applicableContextClasses(),
                candidate.thresholds().minimumEvidenceCount(),
                confidenceBand(metrics),
                metrics.localLiftRate(),
                metrics.fpDelta(),
                metrics.fnDelta(),
                metrics.sampleSize(),
                metrics.outcomeCoverageRate(),
                metrics.hardNegativeCoverage(),
                metadata.isRuntimeEligible(),
                metadata.releaseState().name(),
                metadata.guardrails().stream().map(LearningArtifactGuardrail::summary).toList(),
                candidate.familyResult().evidenceFacts(),
                candidate.qualificationDecision().policyFacts());
    }

    private DetectionStrategyRuntimePack.RuntimeStrategyItem toRuntimeItem(DetectionStrategyPackCandidate candidate) {
        StrategyProfile profile = profile(candidate.familyResult().strategyFamily());
        return new DetectionStrategyRuntimePack.RuntimeStrategyItem(
                strategyKey(candidate.familyResult().strategyFamily()),
                DEFAULT_VERSION,
                candidate.familyResult().strategyFamily(),
                profile.supportedThreatGoals(),
                profile.requiredSignals(),
                profile.recommendedSignals(),
                profile.applicableContextClasses(),
                candidate.thresholds().minimumEvidenceCount(),
                confidenceBand(candidate.metadata().metrics()),
                candidate.metadata(),
                candidate.familyResult().evidenceFacts(),
                candidate.qualificationDecision().policyFacts());
    }

    private StrategyProfile profile(String family) {
        if (family == null) {
            return StrategyProfile.generic();
        }
        return PROFILES.getOrDefault(family.trim().toUpperCase(Locale.ROOT), StrategyProfile.generic());
    }

    private String confidenceBand(LearningArtifactMetrics metrics) {
        LearningArtifactMetrics current = metrics == null ? LearningArtifactMetrics.empty() : metrics;
        if (current.outcomeCoverageRate() >= 0.75d && current.hardNegativeCoverage() >= 0.15d && current.localLiftRate() >= 0.10d) {
            return "HIGH";
        }
        if (current.outcomeCoverageRate() >= 0.60d && current.localLiftRate() >= 0.05d) {
            return "MODERATE";
        }
        return "LOW";
    }

    private String summarizePromotionState(List<DetectionStrategyPackCandidate> candidates) {
        return candidates.stream()
                .map(DetectionStrategyPackCandidate::metadata)
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

    private String strategyKey(String family) {
        if (family == null || family.isBlank()) {
            return "detection-strategy/unclassified";
        }
        return "detection-strategy/" + family.trim().toLowerCase(Locale.ROOT).replace('_', '-');
    }

    private static Map<String, StrategyProfile> buildProfiles() {
        Map<String, StrategyProfile> profiles = new LinkedHashMap<>();
        profiles.put("PATH_SEQUENCE_DIVERGENCE", new StrategyProfile(
                List.of("ACCOUNT_TAKEOVER", "SESSION_TAKEOVER", "DATA_EXFILTRATION"),
                List.of("requestPath", "previousPath", "signalKeys"),
                List.of("promptAuditLinked", "recentRequestCount", "deniedContextCount"),
                List.of("SEQUENCE_BREAK", "SENSITIVE_APPROACH")));
        profiles.put("SESSION_ENTROPY_COLLAPSE", new StrategyProfile(
                List.of("SESSION_TAKEOVER", "AUTOMATED_ABUSE"),
                List.of("requestPath", "signalKeys"),
                List.of("layer1EscalationRate", "challengeRate", "blockRate"),
                List.of("LOW_DIVERSITY_SESSION", "COLLAPSED_SESSION_SPREAD")));
        profiles.put("POST_MFA_SURFACE_JUMP", new StrategyProfile(
                List.of("ACCOUNT_TAKEOVER", "SESSION_TAKEOVER"),
                List.of("mfaVerified", "requestPath", "resourceSensitivity"),
                List.of("reasonCategory", "newDevice", "recentRequestCount"),
                List.of("POST_MFA_SENSITIVE", "MFA_FRESH_SESSION")));
        profiles.put("INITIAL_REQUEST_PROFILE_DELTA", new StrategyProfile(
                List.of("ACCOUNT_TAKEOVER", "SESSION_TAKEOVER"),
                List.of("newDevice", "requestPath", "resourceSensitivity"),
                List.of("personalBaselineEstablished", "organizationBaselineEstablished", "previousPath"),
                List.of("NEW_DEVICE_INITIAL_SEQUENCE", "COLD_START_ACCOUNT")));
        profiles.put("SCOPE_EXPANSION_SEQUENCE", new StrategyProfile(
                List.of("PRIVILEGE_ABUSE", "DATA_EXFILTRATION"),
                List.of("requestPath", "resourceSensitivity", "reasonCategory"),
                List.of("previousPath", "targetSurfaces", "signalKeys"),
                List.of("PRIVILEGED_SURFACE_DISCOVERY", "EXPORT_APPROACH")));
        return Map.copyOf(profiles);
    }

    private record StrategyProfile(
            List<String> supportedThreatGoals,
            List<String> requiredSignals,
            List<String> recommendedSignals,
            List<String> applicableContextClasses) {

        private StrategyProfile {
            supportedThreatGoals = supportedThreatGoals == null ? List.of() : List.copyOf(supportedThreatGoals);
            requiredSignals = requiredSignals == null ? List.of() : List.copyOf(requiredSignals);
            recommendedSignals = recommendedSignals == null ? List.of() : List.copyOf(recommendedSignals);
            applicableContextClasses = applicableContextClasses == null ? List.of() : List.copyOf(applicableContextClasses);
        }

        private static StrategyProfile generic() {
            return new StrategyProfile(
                    List.of("ACCOUNT_TAKEOVER"),
                    List.of("requestPath", "signalKeys"),
                    List.of("promptAuditLinked", "recentRequestCount"),
                    List.of("GENERIC_STRATEGY_CONTEXT"));
        }
    }
}
