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
package io.contexa.contexacore.monitoring.ai;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.DecisionFact;
import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
import io.contexa.contexacore.autonomous.context.decision.Deviation;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionOutputContract;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionOutputContractV4;
import io.contexa.contexacore.util.SensitiveValueSanitizer;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * The console columns of one decision row (console design 7.1), read from what the engine already put on the event and
 * the processing result: the attempt it was, the stage and source of the action, when it takes effect, who acted and
 * on what, the bundle, the most likely explanation, how much context the model had, the tokens and calls, and the
 * summary the decision detail shows. Nothing here changes a decision; a value the engine did not keep stays null.
 */
public final class DecisionConsoleColumns {

    /** The most a decision summary keeps, in characters. */
    static final int SUMMARY_LIMIT = 16_000;

    public static final String ATTEMPT_FIRST = "FIRST";
    public static final String ATTEMPT_RETRY = "RETRY";
    public static final String ATTEMPT_AGAIN = "AGAIN";
    public static final String ATTEMPT_TIMEOUT = "TIMEOUT";
    public static final String ATTEMPT_REJECTED = "REJECTED";

    public static final String SOURCE_MODEL = "MODEL";
    public static final String SOURCE_ENGINE_CHANGED = "ENGINE_CHANGED";
    public static final String SOURCE_MODEL_LESS = "MODEL_LESS";

    public static final String TIMING_BEFORE_RESPONSE = "BEFORE_RESPONSE";
    public static final String TIMING_NEXT_REQUEST = "NEXT_REQUEST";

    /** The decision's console columns, in the order the writer inserts them. */
    public record Values(String attemptKind, String originalEventId, String decisionStage, String analysisDepth,
                         String decisionSource, String decisionChangeCause, String enforcementTiming, String actorKind,
                         String resourceClass, String promptBundleVersion, String mostLikelyHypothesis,
                         String contextCoverageLevel, String baselineStatus, Integer unknownFactCount, Long promptTokens,
                         Long cachedPromptTokens, Long outputTokens, Integer modelCallCount, Long userWaitMs,
                         Long providerThrottleWaitMs, Boolean providerThrottleAcquired, String providerThrottleReason,
                         Long providerEstimatedTokens, Map<String, Object> summary, List<Reason> reasons) {
    }

    /** One reason code the model gave, with the fact it cites. */
    public record Reason(int rank, String code, String group, String factId, String factName) {
    }

    private DecisionConsoleColumns() {
    }

    public static Values of(Map<String, Object> metadata, ProcessingResult result, ZeroTrustAction finalAction,
                            Instant now) {
        Map<String, Object> meta = metadata == null ? Map.of() : metadata;
        CanonicalSecurityContext context = meta.get("sealedEvidence.canonicalContext")
                instanceof CanonicalSecurityContext decided ? decided : null;
        DecisionFacts facts = context != null ? context.getDecisionFacts() : null;
        String attempt = attemptKind(meta, finalAction);
        String originalEventId = text(meta.get("judgedAgainEvent"));
        String stage = result != null && result.getAnalysisData() != null
                ? text(result.getAnalysisData().get("decisionAppliedStage")) : null;
        String depth = result != null && result.getAiAnalysisLevel() > 0 ? String.valueOf(result.getAiAnalysisLevel()) : null;
        String[] source = decisionSource(meta, result, stage);
        String timing = enforcementTiming(meta);
        List<Reason> reasons = reasons(result, facts);
        Long promptTokens = sum(longValue(meta.get("layer1ActualPromptTokens")), longValue(meta.get("layer2ActualPromptTokens")));
        if (promptTokens == null) {
            promptTokens = longValue(meta.get("actualPromptTokens"));
        }
        Long throttleWait = longValue(meta.get("providerThrottleWaitMs"));
        Boolean throttleEnabled = bool(meta.get("providerThrottleEnabled"));
        Long waited = TIMING_BEFORE_RESPONSE.equals(timing) ? waitedSince(meta.get("ingestAt"), now) : null;
        return new Values(
                attempt,
                originalEventId,
                stage,
                depth,
                source[0],
                source[1],
                timing,
                actorKind(text(meta.get("executionSubjectKind"))),
                resourceClass(context, meta),
                text(meta.get("promptBundleSelection.version")),
                mostLikely(result),
                context != null && context.getCoverage() != null && context.getCoverage().level() != null
                        ? context.getCoverage().level().name() : null,
                baselineStatus(context, meta),
                facts != null ? Integer.valueOf(facts.unknown().size())
                        : sizeOf(meta.get("promptEvidenceCompletenessReasons")),
                promptTokens,
                longValue(meta.get("cachedPromptTokens")),
                longValue(meta.get("actualCompletionTokens")),
                modelCalls(meta),
                waited,
                throttleWait,
                throttleEnabled == null ? null : Boolean.TRUE.equals(throttleEnabled) && throttleWait != null,
                truncate(text(meta.get("providerThrottleSkippedReason")), 128),
                longValue(meta.get("providerThrottleEstimatedTokens")),
                summary(result, facts, meta, reasons),
                reasons);
    }

    /**
     * Console design 5: a decision counts once. A row the engine wrote for a timeout or a rejection holds no decision; a
     * re-judgement of a model-less challenge and a retry that writes a kept result again are the same request once more.
     */
    static String attemptKind(Map<String, Object> meta, ZeroTrustAction finalAction) {
        String failure = text(meta.get("decisionFailureCategory"));
        if (finalAction == ZeroTrustAction.PENDING_ANALYSIS || Boolean.TRUE.equals(bool(meta.get("lateProcessingResultDiscarded")))) {
            if ("REJECTED_BACKPRESSURE".equals(failure)) {
                return ATTEMPT_REJECTED;
            }
            return ATTEMPT_TIMEOUT;
        }
        if (text(meta.get("judgedAgainEvent")) != null) {
            return ATTEMPT_AGAIN;
        }
        if (Boolean.TRUE.equals(bool(meta.get("decisionAuditPending")))) {
            return ATTEMPT_RETRY;
        }
        return ATTEMPT_FIRST;
    }

    /**
     * Who set the action (console design 6.3): the model; the engine, over the model's answer (the second analysis
     * ended an ESCALATE, the escalation protection); no model (a technical fallback, an answer in no usable form, a
     * contract fallback). A stricter action kept in force is known only after the store and is set then.
     */
    static String[] decisionSource(Map<String, Object> meta, ProcessingResult result, String stage) {
        if (result != null && Boolean.TRUE.equals(result.getTechnicalFallbackApplied())
                || Boolean.FALSE.equals(bool(meta.get("rawExecutionSucceeded")))
                || result != null && Boolean.FALSE.equals(result.getLlmDecisionPresent())) {
            String category = result != null ? text(result.getTechnicalFallbackCategory()) : null;
            return new String[] {SOURCE_MODEL_LESS, truncate(category != null ? category : "TECHNICAL_FALLBACK", 64)};
        }
        if (text(meta.get("securityDecisionContractFallbackAction")) != null) {
            return new String[] {SOURCE_MODEL_LESS, "CONTRACT_FALLBACK"};
        }
        if (result != null && Boolean.TRUE.equals(result.getResponseActionFallbackApplied())) {
            String category = text(result.getResponseActionFallbackCategory());
            return new String[] {SOURCE_MODEL_LESS, truncate(category != null ? category : "RESPONSE_FORMAT", 64)};
        }
        if (result != null && result.getAutonomyConstraintReasons() != null
                && result.getAutonomyConstraintReasons().contains("LAYER2_ESCALATE_TERMINALIZED")) {
            return new String[] {SOURCE_ENGINE_CHANGED, "LAYER2_ESCALATE_TERMINALIZED"};
        }
        if ("ESCALATE_PROTECTION".equals(stage)) {
            return new String[] {SOURCE_ENGINE_CHANGED, "ESCALATE_PROTECTION"};
        }
        if (result != null && Boolean.TRUE.equals(result.getAutonomyConstraintApplied())) {
            return new String[] {SOURCE_ENGINE_CHANGED, "AUTONOMY_CONSTRAINT"};
        }
        return new String[] {SOURCE_MODEL, null};
    }

    /**
     * When the action takes effect (console design 5): before the response for a synchronous decision, from the next
     * request for an asynchronous one, whose first request has gone by. The queue of the asynchronous analysis leaves
     * its marks; a synchronous decision has none.
     */
    static String enforcementTiming(Map<String, Object> meta) {
        if (Boolean.TRUE.equals(bool(meta.get("protectableSync")))) {
            return TIMING_BEFORE_RESPONSE;
        }
        boolean queued = meta.get("analysisQueuedAt") != null || meta.get("stripeId") != null;
        return queued ? TIMING_NEXT_REQUEST : TIMING_BEFORE_RESPONSE;
    }

    static String actorKind(String subjectKind) {
        if (subjectKind == null) {
            return null;
        }
        return switch (subjectKind.toUpperCase(Locale.ROOT)) {
            case "DELEGATED_AGENT", "AUTONOMOUS_AGENT" -> "AGENT";
            case "SERVICE_CLIENT" -> "SERVICE";
            default -> "HUMAN";
        };
    }

    static String resourceClass(CanonicalSecurityContext context, Map<String, Object> meta) {
        if (context != null && context.getResource() != null && text(context.getResource().getResourceClass()) != null) {
            return truncate(context.getResource().getResourceClass().toUpperCase(Locale.ROOT), 32);
        }
        if (Boolean.TRUE.equals(bool(meta.get("isSensitiveResource")))) {
            return "SENSITIVE";
        }
        return null;
    }

    static String baselineStatus(CanonicalSecurityContext context, Map<String, Object> meta) {
        if (context != null && context.getWorkProfile() != null && context.getWorkProfile().getBaselineView() != null
                && context.getWorkProfile().getBaselineView().state() != null) {
            return context.getWorkProfile().getBaselineView().state().name();
        }
        Boolean established = bool(meta.get("learningPersonalBaselineEstablished"));
        return established == null ? null : established ? "ESTABLISHED" : "NONE";
    }

    /** The hypothesis the model marked most likely (v21 and v1.0); the first when it marked several, null for none. */
    static String mostLikely(ProcessingResult result) {
        if (result == null || result.getHypotheses() == null) {
            return null;
        }
        for (Map<String, Object> hypothesis : result.getHypotheses()) {
            if (hypothesis != null && "MOST_LIKELY".equalsIgnoreCase(text(hypothesis.get("assessment")))) {
                String id = text(hypothesis.get("id"));
                return id != null ? truncate(id.toUpperCase(Locale.ROOT), 16) : null;
            }
        }
        return null;
    }

    /** The model calls of the decision: one per layer and one per corrective retry. */
    static Integer modelCalls(Map<String, Object> meta) {
        Integer stages = sizeOf(meta.get("modelCallStages"));
        Integer retries = sizeOf(meta.get("securityDecisionOutputRetries"));
        if (stages == null && retries == null) {
            return null;
        }
        return (stages == null ? 0 : stages) + (retries == null ? 0 : retries);
    }

    static List<Reason> reasons(ProcessingResult result, DecisionFacts facts) {
        List<Reason> reasons = new ArrayList<>();
        if (result == null || result.getReasonCodes() == null) {
            return reasons;
        }
        int rank = 1;
        for (SecurityDecisionOutputContract.Citation citation : result.getReasonCodes()) {
            if (citation == null || text(citation.code()) == null) {
                continue;
            }
            String code = truncate(citation.code().trim().toUpperCase(Locale.ROOT), 64);
            String factId = truncate(text(citation.fact()), 16);
            reasons.add(new Reason(rank++, code, group(code), factId, factName(facts, factId)));
        }
        return reasons;
    }

    private static String group(String code) {
        return SecurityDecisionOutputContractV4.REASON_CODES.stream()
                .filter(reasonCode -> reasonCode.code().equals(code))
                .map(reasonCode -> reasonCode.group().name())
                .findFirst().orElse(null);
    }

    private static String factName(DecisionFacts facts, String factId) {
        if (facts == null || factId == null) {
            return null;
        }
        return facts.facts().stream().filter(fact -> factId.equalsIgnoreCase(fact.id())).map(DecisionFact::name)
                .findFirst().map(name -> truncate(name, 160)).orElse(null);
    }

    /**
     * What the decision detail shows (console design 6.4): the reason codes with the facts they cite, the explanations
     * the model weighed, the differences from the usual, the unknown facts and the model's sentence. Bounded so a row
     * never carries the whole event.
     */
    static Map<String, Object> summary(ProcessingResult result, DecisionFacts facts, Map<String, Object> meta,
                                       List<Reason> reasons) {
        Map<String, Object> summary = new LinkedHashMap<>();
        List<Map<String, Object>> cited = new ArrayList<>();
        for (Reason reason : reasons) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("code", reason.code());
            item.put("group", reason.group());
            item.put("fact", reason.factId());
            Optional<DecisionFact> fact = facts == null || reason.factId() == null ? Optional.empty()
                    : facts.facts().stream().filter(found -> reason.factId().equalsIgnoreCase(found.id())).findFirst();
            fact.ifPresent(found -> {
                item.put("factName", found.name());
                item.put("factValue", truncate(SensitiveValueSanitizer.sanitizeText(found.value()), 300));
            });
            cited.add(item);
        }
        summary.put("reasons", cited);
        if (result != null && result.getHypotheses() != null) {
            List<Map<String, Object>> hypotheses = new ArrayList<>();
            for (Map<String, Object> hypothesis : result.getHypotheses()) {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("id", hypothesis.get("id"));
                item.put("assessment", hypothesis.get("assessment"));
                item.put("for", hypothesis.get("for"));
                item.put("against", hypothesis.get("against"));
                hypotheses.add(item);
            }
            summary.put("hypotheses", hypotheses);
        }
        if (facts != null) {
            List<Map<String, Object>> deviations = new ArrayList<>();
            for (Deviation deviation : facts.deviations()) {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("dimension", deviation.dimension() != null ? deviation.dimension().name() : null);
                item.put("current", truncate(SensitiveValueSanitizer.sanitizeText(deviation.current()), 200));
                item.put("usual", truncate(SensitiveValueSanitizer.sanitizeText(deviation.usual()), 200));
                item.put("compared", deviation.compared());
                item.put("different", deviation.different());
                item.put("explanation", deviation.explanation() != null ? deviation.explanation().name() : null);
                item.put("explainedBy", deviation.explainedBy());
                deviations.add(item);
            }
            summary.put("deviations", deviations);
            Map<String, Object> unknown = new LinkedHashMap<>();
            for (String name : facts.unknown()) {
                unknown.put(name, facts.unavailable().containsKey(name) ? "UNAVAILABLE_NOW" : "NOT_INTEGRATED");
            }
            summary.put("unknown", unknown);
            summary.put("policySatisfied", facts.policy() != null ? facts.policy().satisfied() : null);
        }
        else if (meta.get("promptEvidenceCompletenessReasons") instanceof Collection<?> unknownReasons) {
            summary.put("unknownReasons", List.copyOf(unknownReasons));
        }
        if (result != null && result.getReasoning() != null) {
            summary.put("reason", truncate(SensitiveValueSanitizer.sanitizeText(result.getReasoning()), 1_000));
        }
        return summary;
    }

    private static Long waitedSince(Object ingestAt, Instant now) {
        Long ingested = longValue(ingestAt);
        if (ingested == null || now == null) {
            return null;
        }
        long waited = now.toEpochMilli() - ingested;
        return waited >= 0 ? waited : null;
    }

    private static Long sum(Long first, Long second) {
        if (first == null && second == null) {
            return null;
        }
        return (first == null ? 0 : first) + (second == null ? 0 : second);
    }

    private static Integer sizeOf(Object value) {
        return value instanceof Collection<?> collection ? collection.size() : null;
    }

    static Long longValue(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value instanceof String text && !text.isBlank()) {
            try {
                return Long.parseLong(text.trim());
            }
            catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private static Boolean bool(Object value) {
        if (value instanceof Boolean flag) {
            return flag;
        }
        if (value instanceof String text && !text.isBlank()) {
            return Boolean.parseBoolean(text.trim());
        }
        return null;
    }

    private static String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isEmpty() ? null : text;
    }

    private static String truncate(String value, int length) {
        return value == null || value.length() <= length ? value : value.substring(0, length);
    }
}
