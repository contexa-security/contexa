package io.contexa.contexacore.autonomous.saas.learning.prompt;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Aggregates presentation-safe prompt experiments without introducing semantic prompt guidance.
 */
public class PromptPresentationExperimentService {

    private final PromptPresentationObservationFactory observationFactory;

    public PromptPresentationExperimentService(PromptPresentationObservationFactory observationFactory) {
        this.observationFactory = Objects.requireNonNull(observationFactory, "observationFactory is required");
    }

    public PromptPresentationExperimentPortfolio evaluate(PromptPresentationExperimentInput input) {
        PromptPresentationObservationBatch batch = observationFactory.create(input == null ? PromptPresentationExperimentInput.empty() : input);
        if (batch.observations().isEmpty()) {
            return new PromptPresentationExperimentPortfolio(
                    batch.promptAuditCount(),
                    0L,
                    batch.unclassifiedAuditCount(),
                    List.of(),
                    LocalDateTime.now());
        }

        Map<String, List<PromptPresentationObservation>> grouped = new LinkedHashMap<>();
        for (PromptPresentationObservation observation : batch.observations()) {
            grouped.computeIfAbsent(observation.patternProfile().patternKey(), ignored -> new ArrayList<>()).add(observation);
        }

        List<PromptPresentationExperimentResult> results = grouped.values().stream()
                .map(this::toResult)
                .sorted(Comparator.comparingLong(PromptPresentationExperimentResult::sampleSize).reversed()
                        .thenComparing(item -> item.patternProfile().patternKey()))
                .toList();

        return new PromptPresentationExperimentPortfolio(
                batch.promptAuditCount(),
                batch.observations().size(),
                batch.unclassifiedAuditCount(),
                results,
                LocalDateTime.now());
    }

    private PromptPresentationExperimentResult toResult(List<PromptPresentationObservation> observations) {
        PromptPresentationPatternProfile patternProfile = observations.get(0).patternProfile();
        long sampleSize = observations.size();
        long operatorReviewedOutcomeCount = observations.stream().filter(PromptPresentationObservation::operatorReviewedOutcome).count();
        long reviewerDisagreementCount = observations.stream().filter(PromptPresentationObservation::reviewerDisagreement).count();
        long falsePositiveOutcomeCount = observations.stream().filter(PromptPresentationObservation::falsePositiveOutcome).count();
        long falseNegativeOutcomeCount = observations.stream().filter(PromptPresentationObservation::falseNegativeOutcome).count();
        long omissionLinkedCount = observations.stream()
                .filter(item -> item.deniedContextCount() > 0 || item.omittedSectionCount() > 0 || item.promptOmissionCount() > 0)
                .count();
        long telemetryLinkedCount = observations.stream()
                .filter(item -> item.promptRuntimeTelemetryLinked() || item.modelPerformanceTelemetryLinked())
                .count();
        double averageDeniedContextCount = observations.stream().mapToInt(PromptPresentationObservation::deniedContextCount).average().orElse(0.0d);
        double averageOmittedSectionCount = observations.stream().mapToInt(PromptPresentationObservation::omittedSectionCount).average().orElse(0.0d);
        double averagePromptBudgetUtilizationRate = observations.stream().mapToDouble(PromptPresentationObservation::promptBudgetUtilizationRate).average().orElse(0.0d);
        return new PromptPresentationExperimentResult(
                patternProfile,
                sampleSize,
                operatorReviewedOutcomeCount,
                reviewerDisagreementCount,
                falsePositiveOutcomeCount,
                falseNegativeOutcomeCount,
                omissionLinkedCount,
                telemetryLinkedCount,
                averageDeniedContextCount,
                averageOmittedSectionCount,
                averagePromptBudgetUtilizationRate,
                buildEvidenceFacts(patternProfile, observations, sampleSize, operatorReviewedOutcomeCount, reviewerDisagreementCount),
                buildPolicyFacts());
    }

    private List<String> buildEvidenceFacts(
            PromptPresentationPatternProfile patternProfile,
            List<PromptPresentationObservation> observations,
            long sampleSize,
            long operatorReviewedOutcomeCount,
            long reviewerDisagreementCount) {
        Set<String> facts = new LinkedHashSet<>();
        facts.add("Pattern " + patternProfile.patternKey() + " has " + sampleSize + " prompt-audit observations.");
        facts.add("Operator-reviewed outcomes=" + operatorReviewedOutcomeCount + ", reviewer disagreement=" + reviewerDisagreementCount + ".");
        observations.stream()
                .flatMap(item -> item.evidenceFacts().stream())
                .filter(text -> text != null && !text.isBlank())
                .limit(6)
                .forEach(facts::add);
        return List.copyOf(facts);
    }

    private List<String> buildPolicyFacts() {
        return List.of(
                "Prompt presentation experiments exclude raw prompt text, prompt hashes, and semantic guidance.",
                "Only structural presentation metadata are eligible: promptKey, templateKey, promptVersion, promptTransformationMode, promptCompressionApplied, promptSectionSet, omittedSections, promptEvidenceCompleteness, promptOmissionCount, promptBudgetUtilizationRate.");
    }
}