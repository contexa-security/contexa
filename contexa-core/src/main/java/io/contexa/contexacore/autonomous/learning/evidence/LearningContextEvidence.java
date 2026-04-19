package io.contexa.contexacore.autonomous.learning.evidence;

import java.util.List;

public record LearningContextEvidence(
        CurrentLearningContextSnapshot current,
        BaselineEvidenceSnapshot personalBaseline,
        BaselineEvidenceSnapshot supportingBaseline,
        List<RetrievedBehaviorEvidence> personalRetrievedEvidence,
        List<RetrievedBehaviorEvidence> supportingRetrievedEvidence,
        ObservedPatternSnapshot observedPatterns,
        List<CurrentVsObservedDeltaSnapshot> currentVsObservedDeltas,
        List<String> carryRequiredFacts,
        List<String> carryMissingFacts) {

    public LearningContextEvidence {
        personalRetrievedEvidence = immutable(personalRetrievedEvidence);
        supportingRetrievedEvidence = immutable(supportingRetrievedEvidence);
        currentVsObservedDeltas = immutable(currentVsObservedDeltas);
        carryRequiredFacts = immutable(carryRequiredFacts);
        carryMissingFacts = immutable(carryMissingFacts);
    }

    public boolean hasComparableEvidence() {
        return !personalRetrievedEvidence.isEmpty() || !supportingRetrievedEvidence.isEmpty();
    }

    public int historicalComparableCount() {
        return personalRetrievedEvidence.size();
    }

    public String historicalComparableScope() {
        if (!personalRetrievedEvidence.isEmpty()) {
            return "PERSONAL_RETRIEVED_SUBSET";
        }
        if (!supportingRetrievedEvidence.isEmpty()) {
            return "NO_DIRECT_PERSONAL_COMPARABLE";
        }
        return "NO_COMPARABLE_EVIDENCE";
    }

    public int supportingComparableCount() {
        return supportingRetrievedEvidence.size();
    }

    public String observedPatternEvidenceScope() {
        boolean baselineAvailable = personalBaseline != null && personalBaseline.available();
        boolean retrievedAvailable = !personalRetrievedEvidence.isEmpty();
        if (baselineAvailable && retrievedAvailable) {
            return "PERSONAL_BASELINE_PLUS_PERSONAL_RETRIEVED";
        }
        if (baselineAvailable) {
            return "PERSONAL_BASELINE_ONLY";
        }
        if (retrievedAvailable) {
            return "PERSONAL_RETRIEVED_SUBSET";
        }
        return "NO_PERSONAL_OBSERVED_PATTERN";
    }

    public RetrievedBehaviorEvidence representativeComparable() {
        if (!personalRetrievedEvidence.isEmpty()) {
            return personalRetrievedEvidence.getFirst();
        }
        if (!supportingRetrievedEvidence.isEmpty()) {
            return supportingRetrievedEvidence.getFirst();
        }
        return null;
    }

    public RetrievedBehaviorEvidence representativeComparable(CurrentVsObservedDeltaSnapshot strongestDelta) {
        RetrievedBehaviorEvidence scopedRepresentative = representativeComparableFrom(personalRetrievedEvidence, strongestDelta);
        if (scopedRepresentative != null) {
            return scopedRepresentative;
        }
        return representativeComparableFrom(supportingRetrievedEvidence, strongestDelta);
    }

    public RetrievedBehaviorEvidence representativeSupportingComparable(CurrentVsObservedDeltaSnapshot strongestDelta) {
        return representativeComparableFrom(supportingRetrievedEvidence, strongestDelta);
    }

    public CurrentVsObservedDeltaSnapshot strongestDelta() {
        return currentVsObservedDeltas.isEmpty() ? null : currentVsObservedDeltas.getFirst();
    }

    public int currentRequestCombinationSeenCount() {
        if (current == null || personalRetrievedEvidence.isEmpty()) {
            return 0;
        }
        return (int) personalRetrievedEvidence.stream()
                .filter(this::matchesCurrentCombination)
                .count();
    }

    public String currentRequestCombinationEvidenceScope() {
        if (!personalRetrievedEvidence.isEmpty()) {
            return "PERSONAL_RETRIEVED_SUBSET";
        }
        if (!supportingRetrievedEvidence.isEmpty()) {
            return "SUPPORTING_REFERENCE_ONLY";
        }
        return "NO_DIRECT_PERSONAL_COMPARABLE";
    }

    public String currentRequestCombinationSummary() {
        if (current == null) {
            return null;
        }
        return joinFacts(
                fact("hour", current.accessHour()),
                fact("auth", current.authenticationType()),
                fact("browser", current.browser()),
                fact("action", current.actionFamily()),
                fact("resource", current.resourceFamily()),
                fact("path", current.pathFamily()));
    }

    public String currentRequestCombinationComparedDimensions() {
        if (current == null) {
            return null;
        }
        return joinDimensions(
                hasText(current.accessHour()) ? "accessHour" : null,
                hasText(current.authenticationType()) ? "authenticationType" : null,
                hasText(current.browser()) ? "browser" : null,
                hasText(current.actionFamily()) ? "actionFamily" : null,
                hasText(current.resourceFamily()) ? "resourceFamily" : null,
                hasText(current.pathFamily()) ? "pathFamily" : null);
    }

    public String currentRequestClosestObservedOverlap() {
        if (current == null || personalRetrievedEvidence.isEmpty()) {
            return null;
        }
        int totalDimensions = combinationDimensionCount(current);
        if (totalDimensions <= 0) {
            return null;
        }
        return bestCombinationOverlap() + "/" + totalDimensions;
    }

    public String strongestCurrentRequestCombinationDelta() {
        if (current == null) {
            return null;
        }
        if (personalRetrievedEvidence.isEmpty()) {
            return "no direct personal combination evidence";
        }
        int totalDimensions = combinationDimensionCount(current);
        int matchedDimensions = bestCombinationOverlap();
        if (totalDimensions <= 0) {
            return null;
        }
        RetrievedBehaviorEvidence representative = representativeCombinationComparable();
        String differingDimensions = summarizeCombinationDifferences(representative);
        return joinFacts(
                fact("closestOverlap", matchedDimensions + "/" + totalDimensions),
                fact("differing", hasText(differingDimensions) ? differingDimensions : "none"));
    }

    public String representativeCombinationSummary() {
        RetrievedBehaviorEvidence representative = representativeCombinationComparable();
        if (representative == null) {
            return null;
        }
        return joinFacts(
                fact("count", String.valueOf(currentRequestCombinationSeenCountForRepresentative(representative))),
                fact("hour", representative.accessHour()),
                fact("auth", representative.authenticationType()),
                fact("browser", representative.browser()),
                fact("action", representative.actionFamily()),
                fact("resource", representative.resourceFamily()),
                fact("path", firstNonBlank(representative.pathFamily(), representative.requestPath())));
    }

    public RetrievedBehaviorEvidence representativeCombinationComparable() {
        if (personalRetrievedEvidence.isEmpty()) {
            return null;
        }
        return personalRetrievedEvidence.stream()
                .sorted((left, right) -> Integer.compare(
                        combinationScore(right),
                        combinationScore(left)))
                .findFirst()
                .orElse(personalRetrievedEvidence.getFirst());
    }

    private static <T> List<T> immutable(List<T> values) {
        return values == null ? List.of() : List.copyOf(values);
    }

    private RetrievedBehaviorEvidence representativeComparableFrom(
            List<RetrievedBehaviorEvidence> source,
            CurrentVsObservedDeltaSnapshot strongestDelta) {
        if (source == null || source.isEmpty()) {
            return null;
        }
        if (strongestDelta == null || strongestDelta.key() == null || strongestDelta.key().isBlank()) {
            return source.getFirst();
        }
        return source.stream()
                .filter(evidence -> supportsDeltaDimension(evidence, strongestDelta.key()))
                .findFirst()
                .orElse(source.getFirst());
    }

    private boolean supportsDeltaDimension(RetrievedBehaviorEvidence evidence, String deltaKey) {
        if (evidence == null || deltaKey == null) {
            return false;
        }
        return switch (deltaKey) {
            case "accessHour" -> hasText(evidence.accessHour());
            case "dayOfWeek" -> hasText(evidence.accessDay());
            case "network" -> hasText(evidence.ipBand()) || hasText(evidence.sourceIp());
            case "browser" -> hasText(evidence.browser());
            case "operatingSystem" -> hasText(evidence.operatingSystem());
            case "pathFamily" -> hasText(evidence.pathFamily());
            case "authenticationType" -> hasText(evidence.authenticationType());
            case "actionFamily" -> hasText(evidence.actionFamily());
            case "resourceFamily" -> hasText(evidence.resourceFamily());
            default -> false;
        };
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private boolean matchesCurrentCombination(RetrievedBehaviorEvidence evidence) {
        return combinationScore(evidence) == combinationDimensionCount(current);
    }

    private int bestCombinationOverlap() {
        return personalRetrievedEvidence.stream()
                .mapToInt(this::combinationScore)
                .max()
                .orElse(0);
    }

    private int combinationScore(RetrievedBehaviorEvidence evidence) {
        if (evidence == null || current == null) {
            return 0;
        }
        int score = 0;
        if (matches(current.accessHour(), evidence.accessHour())) {
            score++;
        }
        if (matches(current.authenticationType(), evidence.authenticationType())) {
            score++;
        }
        if (matches(current.browser(), evidence.browser())) {
            score++;
        }
        if (matches(current.actionFamily(), evidence.actionFamily())) {
            score++;
        }
        if (matches(current.resourceFamily(), evidence.resourceFamily())) {
            score++;
        }
        if (matches(current.pathFamily(), evidence.pathFamily())) {
            score++;
        }
        return score;
    }

    private int combinationDimensionCount(CurrentLearningContextSnapshot current) {
        if (current == null) {
            return 0;
        }
        int count = 0;
        if (hasText(current.accessHour())) {
            count++;
        }
        if (hasText(current.authenticationType())) {
            count++;
        }
        if (hasText(current.browser())) {
            count++;
        }
        if (hasText(current.actionFamily())) {
            count++;
        }
        if (hasText(current.resourceFamily())) {
            count++;
        }
        if (hasText(current.pathFamily())) {
            count++;
        }
        return count;
    }

    private int currentRequestCombinationSeenCountForRepresentative(RetrievedBehaviorEvidence representative) {
        if (representative == null || personalRetrievedEvidence.isEmpty()) {
            return 0;
        }
        return (int) personalRetrievedEvidence.stream()
                .filter(candidate -> matches(representative.accessHour(), candidate.accessHour()))
                .filter(candidate -> matches(representative.authenticationType(), candidate.authenticationType()))
                .filter(candidate -> matches(representative.browser(), candidate.browser()))
                .filter(candidate -> matches(representative.actionFamily(), candidate.actionFamily()))
                .filter(candidate -> matches(representative.resourceFamily(), candidate.resourceFamily()))
                .filter(candidate -> matches(representative.pathFamily(), candidate.pathFamily()))
                .count();
    }

    private String summarizeCombinationDifferences(RetrievedBehaviorEvidence representative) {
        if (current == null || representative == null) {
            return null;
        }
        return joinDimensions(
                matches(current.accessHour(), representative.accessHour()) ? null : "accessHour",
                matches(current.authenticationType(), representative.authenticationType()) ? null : "authenticationType",
                matches(current.browser(), representative.browser()) ? null : "browser",
                matches(current.actionFamily(), representative.actionFamily()) ? null : "actionFamily",
                matches(current.resourceFamily(), representative.resourceFamily()) ? null : "resourceFamily",
                matches(current.pathFamily(), representative.pathFamily()) ? null : "pathFamily");
    }

    private boolean matches(String left, String right) {
        return hasText(left) && hasText(right) && left.equalsIgnoreCase(right);
    }

    private String fact(String key, String value) {
        return hasText(value) ? key + "=" + value : null;
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (hasText(value)) {
                return value;
            }
        }
        return null;
    }

    private String joinFacts(String... facts) {
        if (facts == null) {
            return null;
        }
        String joined = java.util.Arrays.stream(facts)
                .filter(this::hasText)
                .reduce((left, right) -> left + " | " + right)
                .orElse(null);
        return hasText(joined) ? joined : null;
    }

    private String joinDimensions(String... dimensions) {
        if (dimensions == null) {
            return null;
        }
        String joined = java.util.Arrays.stream(dimensions)
                .filter(this::hasText)
                .reduce((left, right) -> left + ", " + right)
                .orElse(null);
        return hasText(joined) ? joined : null;
    }
}
