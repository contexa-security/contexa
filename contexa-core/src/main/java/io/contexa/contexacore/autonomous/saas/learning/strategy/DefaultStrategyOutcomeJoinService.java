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
package io.contexa.contexacore.autonomous.saas.learning.strategy;

import io.contexa.contexacore.autonomous.saas.dto.DecisionFeedbackPayload;
import io.contexa.contexacore.autonomous.saas.dto.ModelPerformanceTelemetryPayload;
import io.contexa.contexacore.autonomous.saas.dto.PromptContextAuditPayload;
import io.contexa.contexacore.autonomous.saas.dto.ThreatOutcomePayload;
import io.contexa.contexacore.autonomous.saas.threat.ThreatSignalNormalizationService;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Default correlation service for detection strategy learning inputs.
 */
public class DefaultStrategyOutcomeJoinService implements StrategyOutcomeJoinService {

    private final ThreatSignalNormalizationService threatSignalNormalizationService;

    public DefaultStrategyOutcomeJoinService() {
        this(new ThreatSignalNormalizationService());
    }

    DefaultStrategyOutcomeJoinService(ThreatSignalNormalizationService threatSignalNormalizationService) {
        this.threatSignalNormalizationService = Objects.requireNonNull(
                threatSignalNormalizationService,
                "threatSignalNormalizationService is required");
    }

    @Override
    public List<StrategyLearningObservation> join(DetectionStrategyLearningInput input) {
        DetectionStrategyLearningInput safeInput = input == null ? DetectionStrategyLearningInput.empty() : input;
        Map<String, CorrelationWindow> windows = new LinkedHashMap<>();

        for (DecisionFeedbackPayload payload : safeInput.feedback()) {
            if (payload == null) {
                continue;
            }
            windowFor(windows, resolveCorrelationKey(payload.getCorrelationId(), payload.getFeedbackId(), "feedback"))
                    .feedback().add(payload);
        }
        for (ThreatOutcomePayload payload : safeInput.threatOutcomes()) {
            if (payload == null) {
                continue;
            }
            windowFor(windows, resolveCorrelationKey(payload.getCorrelationId(), payload.getOutcomeId(), "outcome"))
                    .outcomes().add(payload);
        }
        for (PromptContextAuditPayload payload : safeInput.promptAudits()) {
            if (payload == null) {
                continue;
            }
            windowFor(windows, resolveCorrelationKey(payload.getCorrelationId(), payload.getAuditId(), "prompt-audit"))
                    .promptAudits().add(payload);
        }
        for (StrategyCampaignObservation payload : safeInput.campaignObservations()) {
            if (payload == null) {
                continue;
            }
            windowFor(windows, resolveCorrelationKey(payload.correlationId(), payload.signalKey(), "campaign"))
                    .campaignObservations().add(payload);
        }

        if (windows.isEmpty()) {
            return List.of();
        }

        List<ModelPerformanceTelemetryPayload> telemetry = sortedTelemetry(safeInput.modelTelemetry());
        return windows.values().stream()
                .sorted(Comparator
                        .comparing(CorrelationWindow::anchorTime, Comparator.nullsLast(Comparator.reverseOrder()))
                        .thenComparing(CorrelationWindow::correlationId))
                .map(window -> toObservation(window, selectTelemetry(window, telemetry)))
                .toList();
    }

    private CorrelationWindow windowFor(Map<String, CorrelationWindow> windows, String correlationId) {
        return windows.computeIfAbsent(correlationId, CorrelationWindow::new);
    }

    private StrategyLearningObservation toObservation(
            CorrelationWindow window,
            ModelPerformanceTelemetryPayload telemetry) {
        DecisionFeedbackPayload feedback = latestFeedback(window.feedback());
        ThreatOutcomePayload outcome = latestOutcome(window.outcomes());
        PromptContextAuditPayload promptAudit = latestPromptAudit(window.promptAudits());
        String requestPath = firstNonBlank(
                extractText(attributes(outcome), "requestPath", "requestUri"),
                extractText(attributes(feedback), "requestPath", "requestUri"),
                promptAudit != null ? promptAudit.getRequestPath() : null);
        boolean telemetryLinked = telemetry != null || hasPromptRuntimeTelemetry(window.promptAudits());
        boolean xaiLinked = isXaiLinked(window, promptAudit, feedback, outcome);
        List<String> signalKeys = buildSignalKeys(window, outcome);
        Map<String, Object> strategySignals = buildStrategySignals(
                window,
                feedback,
                outcome,
                promptAudit,
                telemetry,
                requestPath,
                signalKeys,
                xaiLinked);
        return new StrategyLearningObservation(
                window.correlationId(),
                feedback != null ? feedback.getFeedbackType() : null,
                firstNonBlank(
                        outcome != null ? outcome.getOriginalAction() : null,
                        feedback != null ? feedback.getOriginalAction() : null),
                firstNonBlank(
                        outcome != null ? outcome.getFinalAction() : null,
                        feedback != null ? feedback.getOverriddenAction() : null,
                        feedback != null ? feedback.getOriginalAction() : null),
                outcome != null ? outcome.getOutcomeType() : null,
                outcome != null ? outcome.getFinalDisposition() : null,
                feedback != null ? feedback.getAiAnalysisLevel() : null,
                !window.promptAudits().isEmpty(),
                totalDeniedContextCount(window.promptAudits()),
                telemetryLinked,
                telemetry != null ? telemetry.getLayer1EscalationRate() : 0.0d,
                telemetry != null ? telemetry.getBlockRate() : 0.0d,
                telemetry != null ? telemetry.getChallengeRate() : 0.0d,
                !window.campaignObservations().isEmpty(),
                signalKeys,
                strategySignals,
                buildEvidenceFacts(window, feedback, outcome, promptAudit, telemetry, requestPath, xaiLinked, signalKeys));
    }

    private List<String> buildSignalKeys(CorrelationWindow window, ThreatOutcomePayload outcome) {
        LinkedHashSet<String> signalKeys = new LinkedHashSet<>();
        if (outcome != null) {
            signalKeys.addAll(extractStringList(attributes(outcome).get("threatKnowledgeSignalKeys")));
            signalKeys.addAll(extractStringList(attributes(outcome).get("threatKnowledgeKeys")));
        }
        for (StrategyCampaignObservation campaignObservation : window.campaignObservations()) {
            if (hasText(campaignObservation.signalKey())) {
                signalKeys.add(campaignObservation.signalKey().trim());
            }
        }
        return List.copyOf(signalKeys);
    }

    private Map<String, Object> buildStrategySignals(
            CorrelationWindow window,
            DecisionFeedbackPayload feedback,
            ThreatOutcomePayload outcome,
            PromptContextAuditPayload promptAudit,
            ModelPerformanceTelemetryPayload telemetry,
            String requestPath,
            List<String> signalKeys,
            boolean xaiLinked) {
        Map<String, Object> signals = new LinkedHashMap<>();
        Map<String, Object> feedbackAttributes = attributes(feedback);
        Map<String, Object> outcomeAttributes = attributes(outcome);
        Map<String, Object> promptRuntimeTelemetry = mergedPromptRuntimeTelemetry(window.promptAudits());
        List<String> campaignThreatClasses = window.campaignObservations().stream()
                .map(StrategyCampaignObservation::canonicalThreatClass)
                .filter(this::hasText)
                .map(String::trim)
                .distinct()
                .toList();
        List<String> campaignGeoCountries = window.campaignObservations().stream()
                .map(StrategyCampaignObservation::geoCountry)
                .filter(this::hasText)
                .map(String::trim)
                .distinct()
                .toList();
        List<String> deniedReasons = window.promptAudits().stream()
                .flatMap(item -> safeList(item.getDeniedReasons()).stream())
                .filter(this::hasText)
                .map(String::trim)
                .distinct()
                .toList();

        putIfNotBlank(signals, "correlationId", window.correlationId());
        putIfNotBlank(signals, "requestPath", requestPath);
        putIfNotBlank(signals, "pathCategory", threatSignalNormalizationService.classifyTargetSurface(requestPath));
        putIfNotBlank(signals, "resourceId", promptAudit != null ? promptAudit.getResourceId() : null);
        putIfNotBlank(signals, "retrievalPurpose", promptAudit != null ? promptAudit.getRetrievalPurpose() : null);
        putIfNotBlank(signals, "promptKey", promptAudit != null ? promptAudit.getPromptKey() : null);
        putIfNotBlank(signals, "templateKey", promptAudit != null ? promptAudit.getTemplateKey() : null);
        putIfNotBlank(signals, "promptVersion", promptAudit != null ? promptAudit.getPromptVersion() : null);
        putIfNotBlank(signals, "contextFingerprint", promptAudit != null ? promptAudit.getContextFingerprint() : null);
        putIfNotBlank(signals, "promptRuntimeTelemetryLayer", promptAudit != null ? promptAudit.getPromptRuntimeTelemetryLayer() : null);
        if (promptAudit != null) {
            signals.put("requestedDocumentCount", promptAudit.getRequestedDocumentCount());
            signals.put("allowedDocumentCount", promptAudit.getAllowedDocumentCount());
            signals.put("deniedDocumentCount", totalDeniedContextCount(window.promptAudits()));
        }
        if (!deniedReasons.isEmpty()) {
            signals.put("deniedReasons", deniedReasons);
        }
        if (!promptRuntimeTelemetry.isEmpty()) {
            signals.put("promptRuntimeTelemetry", promptRuntimeTelemetry);
        }
        putIfPresent(signals, "promptEvidenceCompleteness", promptRuntimeTelemetry.get("promptEvidenceCompleteness"));
        putIfPresent(signals, "promptSectionSet", promptRuntimeTelemetry.get("promptSectionSet"));
        putIfPresent(signals, "omittedSections", promptRuntimeTelemetry.get("omittedSections"));
        putIfPresent(signals, "promptOmissionCount", promptRuntimeTelemetry.get("promptOmissionCount"));
        putIfPresent(signals, "selectedModelId", promptRuntimeTelemetry.get("selectedModelId"));
        putIfPresent(signals, "runtimeModelId", promptRuntimeTelemetry.get("runtimeModelId"));

        putIfPresent(signals, "failedLoginAttempts", firstNonNull(
                extractInteger(outcomeAttributes, "failedLoginAttempts", "auth.failure_count"),
                extractInteger(feedbackAttributes, "failedLoginAttempts", "auth.failure_count")));
        putIfPresent(signals, "isImpossibleTravel", firstNonNull(
                extractBooleanObject(outcomeAttributes, "isImpossibleTravel"),
                extractBooleanObject(feedbackAttributes, "isImpossibleTravel")));
        putIfPresent(signals, "isNewDevice", firstNonNull(
                extractBooleanObject(outcomeAttributes, "isNewDevice"),
                extractBooleanObject(feedbackAttributes, "isNewDevice")));
        putIfPresent(signals, "isSensitiveResource", firstNonNull(
                extractBooleanObject(outcomeAttributes, "isSensitiveResource"),
                extractBooleanObject(feedbackAttributes, "isSensitiveResource")));
        putIfPresent(signals, "geoCountry", firstNonBlank(
                extractText(outcomeAttributes, "geoCountry"),
                extractText(feedbackAttributes, "geoCountry"),
                campaignGeoCountries.isEmpty() ? null : campaignGeoCountries.get(0)));
        putIfPresent(signals, "threatKnowledgeApplied", extractBooleanObject(outcomeAttributes, "threatKnowledgeApplied"));
        putIfPresent(signals, "reasoningMemoryApplied", extractBooleanObject(outcomeAttributes, "reasoningMemoryApplied"));
        putIfPresent(signals, "baselineSeedApplied", extractBooleanObject(outcomeAttributes, "baselineSeedApplied"));
        putIfPresent(signals, "personalBaselineEstablished", extractBooleanObject(outcomeAttributes, "personalBaselineEstablished"));
        putIfPresent(signals, "organizationBaselineEstablished", extractBooleanObject(outcomeAttributes, "organizationBaselineEstablished"));
        putIfPresent(signals, "aiAnalysisLevel", feedback != null ? feedback.getAiAnalysisLevel() : null);
        putIfPresent(signals, "reasonCategory", extractText(feedbackAttributes, "reasonCategory", "operatorReasonCategory"));
        putIfPresent(signals, "promptAuditLinked", !window.promptAudits().isEmpty());
        putIfPresent(signals, "telemetryLinked", telemetry != null || hasPromptRuntimeTelemetry(window.promptAudits()));
        putIfPresent(signals, "campaignObserved", !window.campaignObservations().isEmpty());
        putIfPresent(signals, "xaiLinked", xaiLinked);
        if (!signalKeys.isEmpty()) {
            signals.put("signalKeys", signalKeys);
        }
        if (!campaignThreatClasses.isEmpty()) {
            signals.put("campaignThreatClasses", campaignThreatClasses);
        }
        if (!campaignGeoCountries.isEmpty()) {
            signals.put("campaignGeoCountries", campaignGeoCountries);
        }
        if (telemetry != null) {
            signals.put("telemetryPeriod", telemetry.getPeriod());
            signals.put("layer1EscalationRate", telemetry.getLayer1EscalationRate());
            signals.put("blockRate", telemetry.getBlockRate());
            signals.put("challengeRate", telemetry.getChallengeRate());
        }
        return signals.isEmpty() ? Map.of() : Map.copyOf(signals);
    }

    private List<String> buildEvidenceFacts(
            CorrelationWindow window,
            DecisionFeedbackPayload feedback,
            ThreatOutcomePayload outcome,
            PromptContextAuditPayload promptAudit,
            ModelPerformanceTelemetryPayload telemetry,
            String requestPath,
            boolean xaiLinked,
            List<String> signalKeys) {
        LinkedHashSet<String> facts = new LinkedHashSet<>();
        if (feedback != null) {
            facts.add(String.format(
                    Locale.ROOT,
                    "Feedback %s kept original=%s and overridden=%s.",
                    defaultText(feedback.getFeedbackType(), "UNKNOWN"),
                    defaultText(feedback.getOriginalAction(), "UNKNOWN"),
                    defaultText(feedback.getOverriddenAction(), "UNKNOWN")));
        }
        if (outcome != null) {
            facts.add(String.format(
                    Locale.ROOT,
                    "Outcome %s ended as %s with final action %s.",
                    defaultText(outcome.getOutcomeType(), "UNKNOWN"),
                    defaultText(outcome.getFinalDisposition(), "UNKNOWN"),
                    defaultText(outcome.getFinalAction(), "UNKNOWN")));
        }
        if (promptAudit != null) {
            facts.add(String.format(
                    Locale.ROOT,
                    "Prompt audit retrieved %d allowed documents and denied %d contexts for %s.",
                    promptAudit.getAllowedDocumentCount(),
                    totalDeniedContextCount(window.promptAudits()),
                    defaultText(promptAudit.getRetrievalPurpose(), "unspecified purpose")));
            if (Boolean.TRUE.equals(promptAudit.getPromptRuntimeTelemetryLinked()) || !safeMap(promptAudit.getPromptRuntimeTelemetry()).isEmpty()) {
                facts.add(String.format(
                        Locale.ROOT,
                        "Prompt runtime telemetry was linked on layer %s.",
                        defaultText(promptAudit.getPromptRuntimeTelemetryLayer(), "UNKNOWN")));
            }
        }
        if (telemetry != null) {
            facts.add(String.format(
                    Locale.ROOT,
                    "Model telemetry period %s reports layer1EscalationRate=%.4f, blockRate=%.4f, challengeRate=%.4f.",
                    defaultText(telemetry.getPeriod() != null ? telemetry.getPeriod().toString() : null, "unknown"),
                    telemetry.getLayer1EscalationRate(),
                    telemetry.getBlockRate(),
                    telemetry.getChallengeRate()));
        }
        if (hasText(requestPath)) {
            facts.add(String.format(
                    Locale.ROOT,
                    "Request path %s maps to surface %s.",
                    requestPath,
                    threatSignalNormalizationService.classifyTargetSurface(requestPath)));
        }
        if (!signalKeys.isEmpty()) {
            facts.add("Signal keys: " + String.join(", ", signalKeys));
        }
        for (StrategyCampaignObservation campaignObservation : window.campaignObservations()) {
            facts.add(String.format(
                    Locale.ROOT,
                    "Campaign %s observed signal %s in %s.",
                    defaultText(campaignObservation.canonicalThreatClass(), "unknown-threat"),
                    defaultText(campaignObservation.signalKey(), "unknown-signal"),
                    defaultText(campaignObservation.geoCountry(), "unknown-region")));
            campaignObservation.facts().stream()
                    .filter(this::hasText)
                    .limit(2)
                    .forEach(facts::add);
        }
        if (xaiLinked) {
            facts.add("Prompt context or attributes carried XAI-linked evidence.");
        }
        return List.copyOf(facts);
    }

    private ModelPerformanceTelemetryPayload selectTelemetry(
            CorrelationWindow window,
            List<ModelPerformanceTelemetryPayload> telemetryPayloads) {
        if (telemetryPayloads.isEmpty()) {
            return null;
        }
        LocalDateTime anchorTime = window.anchorTime();
        if (anchorTime == null) {
            return telemetryPayloads.get(0);
        }
        LocalDate anchorDate = anchorTime.toLocalDate();
        return telemetryPayloads.stream()
                .min(Comparator
                        .comparingLong((ModelPerformanceTelemetryPayload payload) -> telemetryDistanceDays(anchorDate, payload))
                        .thenComparing(ModelPerformanceTelemetryPayload::getGeneratedAt, Comparator.nullsLast(Comparator.reverseOrder()))
                        .thenComparing(ModelPerformanceTelemetryPayload::getPeriod, Comparator.nullsLast(Comparator.reverseOrder())))
                .orElse(telemetryPayloads.get(0));
    }

    private long telemetryDistanceDays(LocalDate anchorDate, ModelPerformanceTelemetryPayload payload) {
        LocalDate telemetryDate = telemetryDate(payload);
        if (anchorDate == null || telemetryDate == null) {
            return Long.MAX_VALUE;
        }
        return Math.abs(ChronoUnit.DAYS.between(anchorDate, telemetryDate));
    }

    private LocalDate telemetryDate(ModelPerformanceTelemetryPayload payload) {
        if (payload == null) {
            return null;
        }
        if (payload.getPeriod() != null) {
            return payload.getPeriod();
        }
        return payload.getGeneratedAt() != null ? payload.getGeneratedAt().toLocalDate() : null;
    }

    private List<ModelPerformanceTelemetryPayload> sortedTelemetry(List<ModelPerformanceTelemetryPayload> telemetryPayloads) {
        if (telemetryPayloads == null || telemetryPayloads.isEmpty()) {
            return List.of();
        }
        return telemetryPayloads.stream()
                .filter(Objects::nonNull)
                .sorted(Comparator
                        .comparing(ModelPerformanceTelemetryPayload::getGeneratedAt, Comparator.nullsLast(Comparator.reverseOrder()))
                        .thenComparing(ModelPerformanceTelemetryPayload::getPeriod, Comparator.nullsLast(Comparator.reverseOrder()))
                        .thenComparing(ModelPerformanceTelemetryPayload::getTelemetryId, Comparator.nullsLast(Comparator.naturalOrder())))
                .toList();
    }

    private DecisionFeedbackPayload latestFeedback(List<DecisionFeedbackPayload> feedback) {
        return feedback.stream()
                .filter(Objects::nonNull)
                .max(Comparator
                        .comparing(DecisionFeedbackPayload::getFeedbackTimestamp, Comparator.nullsLast(Comparator.naturalOrder()))
                        .thenComparing(DecisionFeedbackPayload::getFeedbackId, Comparator.nullsLast(Comparator.naturalOrder())))
                .orElse(null);
    }

    private ThreatOutcomePayload latestOutcome(List<ThreatOutcomePayload> outcomes) {
        return outcomes.stream()
                .filter(Objects::nonNull)
                .max(Comparator
                        .comparing(ThreatOutcomePayload::getOutcomeTimestamp, Comparator.nullsLast(Comparator.naturalOrder()))
                        .thenComparing(ThreatOutcomePayload::getOutcomeId, Comparator.nullsLast(Comparator.naturalOrder())))
                .orElse(null);
    }

    private PromptContextAuditPayload latestPromptAudit(List<PromptContextAuditPayload> promptAudits) {
        return promptAudits.stream()
                .filter(Objects::nonNull)
                .max(Comparator
                        .comparing(PromptContextAuditPayload::getForwardedAt, Comparator.nullsLast(Comparator.naturalOrder()))
                        .thenComparing(PromptContextAuditPayload::getAuditId, Comparator.nullsLast(Comparator.naturalOrder())))
                .orElse(null);
    }

    private int totalDeniedContextCount(List<PromptContextAuditPayload> promptAudits) {
        return promptAudits.stream()
                .filter(Objects::nonNull)
                .mapToInt(PromptContextAuditPayload::getDeniedDocumentCount)
                .sum();
    }

    private Map<String, Object> mergedPromptRuntimeTelemetry(List<PromptContextAuditPayload> promptAudits) {
        Map<String, Object> merged = new LinkedHashMap<>();
        promptAudits.stream()
                .filter(Objects::nonNull)
                .sorted(Comparator
                        .comparing(PromptContextAuditPayload::getForwardedAt, Comparator.nullsLast(Comparator.naturalOrder()))
                        .thenComparing(PromptContextAuditPayload::getAuditId, Comparator.nullsLast(Comparator.naturalOrder())))
                .forEach(payload -> safeMap(payload.getPromptRuntimeTelemetry()).forEach(merged::put));
        return merged.isEmpty() ? Map.of() : Map.copyOf(merged);
    }

    private boolean hasPromptRuntimeTelemetry(List<PromptContextAuditPayload> promptAudits) {
        return promptAudits.stream().anyMatch(payload -> payload != null
                && (Boolean.TRUE.equals(payload.getPromptRuntimeTelemetryLinked())
                || !safeMap(payload.getPromptRuntimeTelemetry()).isEmpty()));
    }

    private boolean isXaiLinked(
            CorrelationWindow window,
            PromptContextAuditPayload promptAudit,
            DecisionFeedbackPayload feedback,
            ThreatOutcomePayload outcome) {
        if (promptAudit != null && promptAudit.getContexts() != null) {
            boolean contextLinked = promptAudit.getContexts().stream()
                    .anyMatch(item -> containsXaiHint(item.getContextType())
                            || containsXaiHint(item.getSourceType())
                            || containsXaiHint(item.getArtifactId())
                            || containsXaiHint(item.getProvenanceSummary()));
            if (contextLinked) {
                return true;
            }
        }
        return hasXaiFacts(attributes(feedback)) || hasXaiFacts(attributes(outcome))
                || window.promptAudits().stream().anyMatch(item -> safeMap(item.getPromptRuntimeTelemetry()).keySet().stream().anyMatch(this::containsXaiHint));
    }

    private boolean hasXaiFacts(Map<String, Object> attributes) {
        return !extractStringList(attributes.get("xaiLinkedFacts")).isEmpty()
                || !extractStringList(attributes.get("xaiFacts")).isEmpty()
                || !extractStringList(attributes.get("xai_linked_facts")).isEmpty();
    }

    private boolean containsXaiHint(String value) {
        return hasText(value) && value.trim().toLowerCase(Locale.ROOT).contains("xai");
    }

    private String resolveCorrelationKey(String correlationId, String fallbackId, String prefix) {
        if (hasText(correlationId)) {
            return correlationId.trim();
        }
        if (hasText(fallbackId)) {
            return prefix + ":" + fallbackId.trim();
        }
        return prefix + ":unknown";
    }

    private Map<String, Object> attributes(DecisionFeedbackPayload payload) {
        return payload == null ? Map.of() : safeMap(payload.getAttributes());
    }

    private Map<String, Object> attributes(ThreatOutcomePayload payload) {
        return payload == null ? Map.of() : safeMap(payload.getAttributes());
    }

    private Map<String, Object> safeMap(Map<String, Object> source) {
        return source == null || source.isEmpty() ? Map.of() : source;
    }

    private List<String> safeList(List<String> values) {
        return values == null || values.isEmpty() ? List.of() : values;
    }

    private String extractText(Map<String, Object> source, String... keys) {
        if (source == null || source.isEmpty()) {
            return null;
        }
        for (String key : keys) {
            Object value = source.get(key);
            if (value != null) {
                String text = String.valueOf(value).trim();
                if (!text.isEmpty()) {
                    return text;
                }
            }
        }
        return null;
    }

    private Integer extractInteger(Map<String, Object> source, String... keys) {
        if (source == null || source.isEmpty()) {
            return null;
        }
        for (String key : keys) {
            Object value = source.get(key);
            if (value instanceof Number number) {
                return number.intValue();
            }
            if (value instanceof String text && hasText(text)) {
                try {
                    return Integer.parseInt(text.trim());
                }
                catch (NumberFormatException ignored) {
                    return null;
                }
            }
        }
        return null;
    }

    private Boolean extractBooleanObject(Map<String, Object> source, String key) {
        if (source == null || source.isEmpty()) {
            return null;
        }
        Object value = source.get(key);
        if (value instanceof Boolean booleanValue) {
            return booleanValue;
        }
        if (value instanceof String text && hasText(text)) {
            return Boolean.parseBoolean(text.trim());
        }
        return null;
    }

    private List<String> extractStringList(Object value) {
        if (value instanceof List<?> list) {
            List<String> normalized = new ArrayList<>();
            for (Object item : list) {
                if (item != null) {
                    String text = String.valueOf(item).trim();
                    if (!text.isEmpty()) {
                        normalized.add(text);
                    }
                }
            }
            return List.copyOf(normalized);
        }
        if (value instanceof String text && hasText(text)) {
            return List.of(text.trim());
        }
        return List.of();
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    @SafeVarargs
    private final <T> T firstNonNull(T... values) {
        if (values == null) {
            return null;
        }
        for (T value : values) {
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private void putIfPresent(Map<String, Object> target, String key, Object value) {
        if (value != null) {
            target.put(key, value);
        }
    }

    private void putIfNotBlank(Map<String, Object> target, String key, String value) {
        if (hasText(value)) {
            target.put(key, value.trim());
        }
    }

    private boolean hasText(String value) {
        return value != null && !value.trim().isEmpty();
    }

    private String defaultText(String value, String fallback) {
        return hasText(value) ? value.trim() : fallback;
    }

    private static final class CorrelationWindow {

        private final String correlationId;
        private final List<DecisionFeedbackPayload> feedback = new ArrayList<>();
        private final List<ThreatOutcomePayload> outcomes = new ArrayList<>();
        private final List<PromptContextAuditPayload> promptAudits = new ArrayList<>();
        private final List<StrategyCampaignObservation> campaignObservations = new ArrayList<>();

        private CorrelationWindow(String correlationId) {
            this.correlationId = correlationId;
        }

        private String correlationId() {
            return correlationId;
        }

        private List<DecisionFeedbackPayload> feedback() {
            return feedback;
        }

        private List<ThreatOutcomePayload> outcomes() {
            return outcomes;
        }

        private List<PromptContextAuditPayload> promptAudits() {
            return promptAudits;
        }

        private List<StrategyCampaignObservation> campaignObservations() {
            return campaignObservations;
        }

        private LocalDateTime anchorTime() {
            LocalDateTime latest = null;
            for (DecisionFeedbackPayload payload : feedback) {
                latest = later(latest, payload != null ? payload.getFeedbackTimestamp() : null);
            }
            for (ThreatOutcomePayload payload : outcomes) {
                latest = later(latest, payload != null ? payload.getOutcomeTimestamp() : null);
            }
            for (PromptContextAuditPayload payload : promptAudits) {
                latest = later(latest, payload != null ? payload.getForwardedAt() : null);
            }
            for (StrategyCampaignObservation payload : campaignObservations) {
                latest = later(latest, payload != null ? payload.observedAt() : null);
            }
            return latest;
        }

        private LocalDateTime later(LocalDateTime current, LocalDateTime candidate) {
            if (current == null) {
                return candidate;
            }
            if (candidate == null) {
                return current;
            }
            return candidate.isAfter(current) ? candidate : current;
        }
    }
}
