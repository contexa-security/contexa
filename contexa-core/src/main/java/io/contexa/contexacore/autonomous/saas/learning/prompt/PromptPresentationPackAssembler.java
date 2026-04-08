package io.contexa.contexacore.autonomous.saas.learning.prompt;

import io.contexa.contexacore.autonomous.saas.dto.PromptPresentationPackSnapshot;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactGuardrail;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactLifecycle;
import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

/**
 * Assembles promotable prompt presentation patterns into transport snapshots.
 */
public class PromptPresentationPackAssembler {

    private static final String DEFAULT_VERSION = "1.0.0";

    public PromptPresentationPackSnapshot assembleSnapshot(
            String tenantId,
            boolean featureEnabled,
            boolean sharingEnabled,
            List<PromptPresentationPackCandidate> candidates) {
        List<PromptPresentationPackCandidate> safeCandidates = candidates == null ? List.of() : List.copyOf(candidates);
        if (safeCandidates.isEmpty()) {
            return PromptPresentationPackSnapshot.empty();
        }

        List<PromptPresentationPackCandidate> promotable = safeCandidates.stream()
                .filter(candidate -> !candidate.biasRiskAssessment().blocksPromotion())
                .toList();
        List<PromptPresentationPackSnapshot.PatternItem> items = promotable.stream()
                .map(this::toSnapshotItem)
                .toList();

        return new PromptPresentationPackSnapshot(
                tenantId,
                featureEnabled,
                sharingEnabled,
                promotable.stream().anyMatch(candidate -> candidate.metadata().isRuntimeEligible()),
                summarizePromotionState(promotable, safeCandidates.size() - promotable.size()),
                promotable.stream().filter(candidate -> candidate.metadata().isPromoted()).count(),
                promotable.size(),
                safeCandidates.size() - promotable.size(),
                items,
                LocalDateTime.now());
    }

    private PromptPresentationPackSnapshot.PatternItem toSnapshotItem(PromptPresentationPackCandidate candidate) {
        PromptPresentationExperimentResult result = candidate.experimentResult();
        PromptPresentationPatternProfile patternProfile = result.patternProfile();
        PromptBiasRiskAssessment assessment = candidate.biasRiskAssessment();
        return new PromptPresentationPackSnapshot.PatternItem(
                patternProfile.patternKey(),
                DEFAULT_VERSION,
                supportedPromptFamilies(patternProfile),
                List.of(),
                new PromptPresentationPackSnapshot.MeasuredDelta(
                        result.sampleSize(),
                        result.operatorReviewedOutcomeCount(),
                        assessment.reviewerDisagreementRate(),
                        assessment.falsePositiveRate(),
                        assessment.falseNegativeRate(),
                        assessment.omissionLinkedRate(),
                        result.averagePromptBudgetUtilizationRate()),
                assessment.biasRiskState().name(),
                supportedContextCoverageBand(patternProfile),
                candidate.metadata().isRuntimeEligible(),
                candidate.metadata().releaseState().name(),
                candidate.metadata().guardrails().stream().map(LearningArtifactGuardrail::summary).toList(),
                result.evidenceFacts(),
                candidate.policyFacts());
    }

    private String summarizePromotionState(List<PromptPresentationPackCandidate> promotable, long blockedCount) {
        if (promotable.isEmpty()) {
            return blockedCount > 0L ? LearningArtifactReleaseState.REVIEW_ONLY.name() : "DISABLED";
        }
        return promotable.stream()
                .map(PromptPresentationPackCandidate::metadata)
                .map(LearningArtifactLifecycle::releaseState)
                .min(this::statePriority)
                .orElse(LearningArtifactReleaseState.SHADOW_READY)
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

    private List<String> supportedPromptFamilies(PromptPresentationPatternProfile patternProfile) {
        LinkedHashSet<String> families = new LinkedHashSet<>();
        if (hasText(patternProfile.promptKey())) {
            families.add(patternProfile.promptKey());
        }
        if (hasText(patternProfile.templateKey())) {
            families.add(patternProfile.templateKey());
        }
        if (families.isEmpty()) {
            families.add("UNCLASSIFIED_PROMPT_PRESENTATION");
        }
        return List.copyOf(families);
    }

    private String supportedContextCoverageBand(PromptPresentationPatternProfile patternProfile) {
        String completeness = patternProfile.evidenceCompleteness();
        if (!hasText(completeness)) {
            return "UNKNOWN";
        }
        String normalized = completeness.trim().toUpperCase(Locale.ROOT);
        return switch (normalized) {
            case "COMPLETE", "FULL" -> "STRONG";
            case "PARTIAL", "MODERATE" -> "MODERATE";
            default -> "LIMITED";
        };
    }

    private boolean hasText(String value) {
        return value != null && !value.trim().isEmpty();
    }
}