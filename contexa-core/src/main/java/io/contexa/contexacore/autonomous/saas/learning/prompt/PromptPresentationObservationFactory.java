package io.contexa.contexacore.autonomous.saas.learning.prompt;

import io.contexa.contexacore.autonomous.saas.dto.DecisionFeedbackPayload;
import io.contexa.contexacore.autonomous.saas.dto.ModelPerformanceTelemetryPayload;
import io.contexa.contexacore.autonomous.saas.dto.PromptContextAuditPayload;
import io.contexa.contexacore.autonomous.saas.dto.ThreatOutcomePayload;
import org.springframework.util.StringUtils;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Builds experiment observations from prompt-audit-safe structural telemetry only.
 */
public class PromptPresentationObservationFactory {

    private static final Set<String> ALLOWED_PRESENTATION_TELEMETRY_KEYS = Set.of(
            "promptKey",
            "templateKey",
            "promptVersion",
            "promptTransformationMode",
            "promptCompressionApplied",
            "promptSectionSet",
            "omittedSections",
            "promptEvidenceCompleteness",
            "promptOmissionCount",
            "promptBudgetUtilizationRate");

    public PromptPresentationObservationBatch create(PromptPresentationExperimentInput input) {
        PromptPresentationExperimentInput safeInput = input == null ? PromptPresentationExperimentInput.empty() : input;
        if (safeInput.promptAudits().isEmpty()) {
            return PromptPresentationObservationBatch.empty();
        }

        Map<String, DecisionFeedbackPayload> feedbackIndex = latestFeedbacks(safeInput.decisionFeedbacks());
        Map<String, ThreatOutcomePayload> outcomeIndex = latestOutcomes(safeInput.threatOutcomes());
        List<ModelPerformanceTelemetryPayload> telemetry = sortedTelemetry(safeInput.performanceTelemetry());

        List<PromptPresentationObservation> observations = new ArrayList<>();
        long unclassified = 0L;
        for (PromptContextAuditPayload audit : safeInput.promptAudits()) {
            if (audit == null) {
                unclassified++;
                continue;
            }
            PromptPresentationPatternProfile patternProfile = toPatternProfile(audit);
            if (!patternProfile.isClassified()) {
                unclassified++;
                continue;
            }
            String correlationId = normalize(firstNonBlank(audit.getCorrelationId(), audit.getAuditId()));
            DecisionFeedbackPayload feedback = correlationId == null ? null : feedbackIndex.get(correlationId);
            ThreatOutcomePayload outcome = correlationId == null ? null : outcomeIndex.get(correlationId);
            ModelPerformanceTelemetryPayload nearestTelemetry = resolveNearestTelemetry(audit.getForwardedAt(), telemetry);
            Map<String, Object> promptTelemetry = safeTelemetry(audit.getPromptRuntimeTelemetry());
            List<String> omittedSections = asStringList(promptTelemetry.get("omittedSections"));
            int deniedContextCount = Math.max(audit.getDeniedDocumentCount(), 0);
            int promptOmissionCount = asInt(promptTelemetry.get("promptOmissionCount"), omittedSections.size());
            double promptBudgetUtilizationRate = asDouble(promptTelemetry.get("promptBudgetUtilizationRate"), 0.0d);
            boolean operatorReviewedOutcome = isOperatorReviewedOutcome(feedback, outcome);
            boolean reviewerDisagreement = hasReviewerDisagreement(feedback, outcome);
            boolean falsePositiveOutcome = hasSignal(feedback, outcome, "FALSE_POSITIVE");
            boolean falseNegativeOutcome = hasSignal(feedback, outcome, "FALSE_NEGATIVE");
            boolean promptRuntimeTelemetryLinked = Boolean.TRUE.equals(audit.getPromptRuntimeTelemetryLinked()) || !promptTelemetry.isEmpty();
            boolean modelPerformanceTelemetryLinked = nearestTelemetry != null;
            observations.add(new PromptPresentationObservation(
                    correlationId,
                    patternProfile,
                    promptRuntimeTelemetryLinked,
                    modelPerformanceTelemetryLinked,
                    operatorReviewedOutcome,
                    reviewerDisagreement,
                    falsePositiveOutcome,
                    falseNegativeOutcome,
                    deniedContextCount,
                    omittedSections.size(),
                    promptOmissionCount,
                    promptBudgetUtilizationRate,
                    buildEvidenceFacts(patternProfile, audit, deniedContextCount, omittedSections, promptOmissionCount, modelPerformanceTelemetryLinked)));
        }

        return new PromptPresentationObservationBatch(
                safeInput.promptAudits().size(),
                unclassified,
                observations);
    }

    private PromptPresentationPatternProfile toPatternProfile(PromptContextAuditPayload audit) {
        Map<String, Object> telemetry = safeTelemetry(audit.getPromptRuntimeTelemetry());
        String promptKey = normalize(firstNonBlank(audit.getPromptKey(), asText(telemetry.get("promptKey"))));
        String templateKey = normalize(firstNonBlank(audit.getTemplateKey(), asText(telemetry.get("templateKey"))));
        String promptVersion = normalize(firstNonBlank(audit.getPromptVersion(), asText(telemetry.get("promptVersion"))));
        String transformationMode = normalize(asText(telemetry.get("promptTransformationMode")));
        boolean compressionApplied = asBoolean(telemetry.get("promptCompressionApplied"));
        String evidenceCompleteness = normalize(asText(telemetry.get("promptEvidenceCompleteness")));
        List<String> sectionSet = asStringList(telemetry.get("promptSectionSet"));
        List<String> omittedSections = asStringList(telemetry.get("omittedSections"));
        if (promptKey == null
                && templateKey == null
                && promptVersion == null
                && transformationMode == null
                && evidenceCompleteness == null
                && !compressionApplied
                && sectionSet.isEmpty()
                && omittedSections.isEmpty()) {
            return PromptPresentationPatternProfile.unclassified();
        }
        return new PromptPresentationPatternProfile(
                buildPatternKey(promptKey, templateKey, promptVersion, transformationMode, compressionApplied, evidenceCompleteness, sectionSet, omittedSections),
                promptKey,
                templateKey,
                promptVersion,
                transformationMode,
                compressionApplied,
                evidenceCompleteness,
                sectionSet,
                omittedSections);
    }

    private String buildPatternKey(
            String promptKey,
            String templateKey,
            String promptVersion,
            String transformationMode,
            boolean compressionApplied,
            String evidenceCompleteness,
            List<String> sectionSet,
            List<String> omittedSections) {
        List<String> parts = new ArrayList<>();
        addPart(parts, "prompt", promptKey);
        addPart(parts, "template", templateKey);
        addPart(parts, "version", promptVersion);
        addPart(parts, "transform", transformationMode);
        parts.add("compression=" + compressionApplied);
        addPart(parts, "coverage", evidenceCompleteness);
        if (!sectionSet.isEmpty()) {
            parts.add("sections=" + String.join("+", sectionSet));
        }
        if (!omittedSections.isEmpty()) {
            parts.add("omissions=" + String.join("+", omittedSections));
        }
        return String.join("|", parts);
    }

    private void addPart(List<String> parts, String key, String value) {
        if (StringUtils.hasText(value)) {
            parts.add(key + "=" + value);
        }
    }

    private Map<String, DecisionFeedbackPayload> latestFeedbacks(List<DecisionFeedbackPayload> payloads) {
        Map<String, DecisionFeedbackPayload> index = new LinkedHashMap<>();
        payloads.stream()
                .filter(Objects::nonNull)
                .sorted(Comparator.comparing(DecisionFeedbackPayload::getFeedbackTimestamp, Comparator.nullsLast(Comparator.naturalOrder()))
                        .thenComparing(DecisionFeedbackPayload::getFeedbackId, Comparator.nullsLast(Comparator.naturalOrder())))
                .forEach(payload -> putIfPresent(index, payload.getCorrelationId(), payload));
        return index;
    }

    private Map<String, ThreatOutcomePayload> latestOutcomes(List<ThreatOutcomePayload> payloads) {
        Map<String, ThreatOutcomePayload> index = new LinkedHashMap<>();
        payloads.stream()
                .filter(Objects::nonNull)
                .sorted(Comparator.comparing(ThreatOutcomePayload::getOutcomeTimestamp, Comparator.nullsLast(Comparator.naturalOrder()))
                        .thenComparing(ThreatOutcomePayload::getOutcomeId, Comparator.nullsLast(Comparator.naturalOrder())))
                .forEach(payload -> putIfPresent(index, payload.getCorrelationId(), payload));
        return index;
    }

    private <T> void putIfPresent(Map<String, T> index, String correlationId, T payload) {
        String key = normalize(correlationId);
        if (key != null) {
            index.put(key, payload);
        }
    }

    private List<ModelPerformanceTelemetryPayload> sortedTelemetry(List<ModelPerformanceTelemetryPayload> payloads) {
        return payloads.stream()
                .filter(Objects::nonNull)
                .sorted(Comparator.comparing(ModelPerformanceTelemetryPayload::getGeneratedAt, Comparator.nullsLast(Comparator.naturalOrder())))
                .toList();
    }

    private ModelPerformanceTelemetryPayload resolveNearestTelemetry(
            LocalDateTime forwardedAt,
            List<ModelPerformanceTelemetryPayload> telemetry) {
        if (forwardedAt == null || telemetry.isEmpty()) {
            return null;
        }
        LocalDate targetDate = forwardedAt.toLocalDate();
        return telemetry.stream()
                .filter(item -> item.getPeriod() != null)
                .min(Comparator.comparingLong(item -> Math.abs(item.getPeriod().toEpochDay() - targetDate.toEpochDay())))
                .orElse(null);
    }

    private boolean isOperatorReviewedOutcome(DecisionFeedbackPayload feedback, ThreatOutcomePayload outcome) {
        return containsToken(outcome != null ? outcome.getResolutionSource() : null, "OPERATOR_REVIEW")
                || containsToken(feedback != null ? feedback.getFeedbackType() : null, "REVIEW")
                || containsToken(feedback != null ? feedback.getAdminAction() : null, "OVERRIDE");
    }

    private boolean hasReviewerDisagreement(DecisionFeedbackPayload feedback, ThreatOutcomePayload outcome) {
        return actionChanged(feedback != null ? feedback.getOriginalAction() : null, feedback != null ? feedback.getOverriddenAction() : null)
                || (containsToken(outcome != null ? outcome.getResolutionSource() : null, "OPERATOR_REVIEW")
                && actionChanged(outcome != null ? outcome.getOriginalAction() : null, outcome != null ? outcome.getFinalAction() : null));
    }

    private boolean hasSignal(DecisionFeedbackPayload feedback, ThreatOutcomePayload outcome, String token) {
        return containsToken(outcome != null ? outcome.getOutcomeType() : null, token)
                || containsToken(outcome != null ? outcome.getFinalDisposition() : null, token)
                || containsToken(feedback != null ? feedback.getFeedbackType() : null, token)
                || containsToken(feedback != null ? feedback.getAdminAction() : null, token);
    }

    private boolean actionChanged(String before, String after) {
        String normalizedBefore = normalize(before);
        String normalizedAfter = normalize(after);
        return normalizedBefore != null && normalizedAfter != null && !normalizedBefore.equalsIgnoreCase(normalizedAfter);
    }

    private boolean containsToken(String value, String token) {
        return StringUtils.hasText(value) && value.trim().toUpperCase(Locale.ROOT).contains(token);
    }

    private List<String> buildEvidenceFacts(
            PromptPresentationPatternProfile patternProfile,
            PromptContextAuditPayload audit,
            int deniedContextCount,
            List<String> omittedSections,
            int promptOmissionCount,
            boolean modelPerformanceTelemetryLinked) {
        LinkedHashSet<String> facts = new LinkedHashSet<>();
        facts.add("Prompt presentation experiment excludes raw prompt text and prompt hashes.");
        facts.add("Only whitelisted structural metadata were used to build the presentation pattern.");
        if (StringUtils.hasText(patternProfile.patternKey())) {
            facts.add("patternKey=" + patternProfile.patternKey());
        }
        facts.add("deniedContextCount=" + deniedContextCount);
        facts.add("promptOmissionCount=" + promptOmissionCount);
        if (!omittedSections.isEmpty()) {
            facts.add("omittedSections=" + String.join(", ", omittedSections));
        }
        if (modelPerformanceTelemetryLinked) {
            facts.add("Nearest model performance telemetry period was linked to the prompt audit observation.");
        }
        if (StringUtils.hasText(audit.getRetrievalPurpose())) {
            facts.add("retrievalPurpose=" + audit.getRetrievalPurpose().trim());
        }
        return List.copyOf(facts);
    }

    private Map<String, Object> safeTelemetry(Map<String, Object> telemetry) {
        if (telemetry == null || telemetry.isEmpty()) {
            return Map.of();
        }
        LinkedHashMap<String, Object> allowed = new LinkedHashMap<>();
        telemetry.forEach((key, value) -> {
            if (ALLOWED_PRESENTATION_TELEMETRY_KEYS.contains(key) && value != null) {
                allowed.put(key, value);
            }
        });
        return allowed;
    }

    private List<String> asStringList(Object value) {
        if (value instanceof List<?> rawList) {
            return rawList.stream()
                    .filter(Objects::nonNull)
                    .map(String::valueOf)
                    .map(String::trim)
                    .filter(text -> !text.isEmpty())
                    .distinct()
                    .toList();
        }
        if (value instanceof String text && !text.isBlank()) {
            return List.of(text.trim());
        }
        return List.of();
    }

    private String asText(Object value) {
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isEmpty() ? null : text;
    }

    private int asInt(Object value, int fallback) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String text && !text.isBlank()) {
            try {
                return Integer.parseInt(text.trim());
            } catch (NumberFormatException ignored) {
                return fallback;
            }
        }
        return fallback;
    }

    private double asDouble(Object value, double fallback) {
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        if (value instanceof String text && !text.isBlank()) {
            try {
                return Double.parseDouble(text.trim());
            } catch (NumberFormatException ignored) {
                return fallback;
            }
        }
        return fallback;
    }

    private boolean asBoolean(Object value) {
        if (value instanceof Boolean booleanValue) {
            return booleanValue;
        }
        if (value instanceof String text && !text.isBlank()) {
            return Boolean.parseBoolean(text.trim());
        }
        return false;
    }

    private String firstNonBlank(String first, String second) {
        return StringUtils.hasText(first) ? first.trim() : normalize(second);
    }

    private String normalize(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}