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
package io.contexa.contexacore.autonomous.context.decision;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.baseline.AgentBaselineView;
import io.contexa.contexacore.autonomous.baseline.BaselineViewCalculator;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
import io.contexa.contexacore.autonomous.execution.ExecutionSubjectTypes;

import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * The learning promotion of the plan (L1, W5-1): which differences an allowed request may not make usual at once. A
 * request on a resource of at least the configured class whose facts name a time, day, network or device difference
 * that no record explains is held: it is learned once the same value is held again on another day, or once the user
 * passes a verification on a request with that value. The identity dimensions and the class order are the ones the
 * minimum action rule P1 counts (a test holds them in agreement; the rule source is part of the prompt bundle).
 */
public final class LearningPromotionPolicy {

    /** The identity dimensions, as the minimum action rule P1 counts them; the device is one dimension. */
    private static final Set<DeviationDimension> IDENTITY = Set.of(
            DeviationDimension.TIME, DeviationDimension.DAY, DeviationDimension.NETWORK, DeviationDimension.DEVICE);
    /** The normalised resource classes from the least to the most sensitive (SecuritySemanticNormalizer). */
    private static final List<String> CLASS_ORDER = List.of("PUBLIC", "NORMAL", "SENSITIVE", "CRITICAL");

    /** The canonical context the decision used, put on the event when the prompt is built. */
    public static final String DECIDED_CONTEXT = "sealedEvidence.canonicalContext";

    /**
     * docs/agent A3-7: the dimensions whose first value an agent's request holds back at any resource class. An agent can
     * repeat a request fast enough to make its own usual behaviour, so a value it brings is learned once it is seen on
     * enough days or verified. The time and the day are left out: an agent works at any hour.
     */
    private static final Set<DeviationDimension> AGENT = Set.of(DeviationDimension.TARGET, DeviationDimension.ACTION,
            DeviationDimension.SIZE, DeviationDimension.RATE, DeviationDimension.NETWORK, DeviationDimension.DEVICE);

    /**
     * The promotion switch and limits (contexa.security.zerotrust.baseline.promotion.*); {@code agentHold} is the
     * agent rule's switch (A3-7, {@code promotion.agent.enabled}).
     */
    public record Settings(boolean enabled, String minResourceClass, int minObservations, int minDistinctDays,
                           boolean verifiedPromotes, boolean agentHold) {

        public static final Settings DEFAULTS = new Settings(true, "SENSITIVE", 2, 2, true, true);

        /** The settings with the agent rule on. */
        public Settings(boolean enabled, String minResourceClass, int minObservations, int minDistinctDays,
                        boolean verifiedPromotes) {
            this(enabled, minResourceClass, minObservations, minDistinctDays, verifiedPromotes, true);
        }
    }

    private LearningPromotionPolicy() {
    }

    /** The differences that hold the request back; empty when the request is learned at once. */
    public static List<Deviation> heldDifferences(CanonicalSecurityContext context, Settings settings) {
        Settings rules = settings != null ? settings : Settings.DEFAULTS;
        if (!rules.enabled() || context == null || context.getDecisionFacts() == null) {
            return List.of();
        }
        // A3-7: an agent's first value is held back at any resource class; a person's rule stays as it was.
        if (rules.agentHold() && agentRequest(context)) {
            return context.getDecisionFacts().unexplained().stream()
                    .filter(deviation -> AGENT.contains(deviation.dimension()) && deviation.current() != null)
                    .toList();
        }
        CanonicalSecurityContext.Resource resource = context.getResource();
        if (!atLeast(resource != null ? resource.getResourceClass() : null, rules.minResourceClass())) {
            return List.of();
        }
        return context.getDecisionFacts().unexplained().stream()
                .filter(deviation -> IDENTITY.contains(deviation.dimension()) && deviation.current() != null)
                .toList();
    }

    /** A held value as the records name it: the dimension and the request's value, {@code DEVICE=Chrome/140 on MAC}. */
    public static String valueOf(Deviation deviation) {
        return deviation.dimension().name() + "=" + deviation.current();
    }

    /**
     * The values that hold the request back, each named so that the same value held on another day is the same
     * (QF-19): what {@link #valueOf} names, except that a target is the target the request names, by its digest, and a
     * size or a rate is the order of magnitude of its count.
     */
    public static List<String> heldValues(CanonicalSecurityContext context, Settings settings) {
        return heldDifferences(context, settings).stream()
                .map(deviation -> heldValueOf(deviation, context))
                .distinct()
                .toList();
    }

    /** The values that hold back the request of the event, from the context its decision used (QF-19). */
    public static List<String> heldValues(SecurityEvent event, Settings settings) {
        if (event == null || event.getMetadata() == null
                || !(event.getMetadata().get(DECIDED_CONTEXT) instanceof CanonicalSecurityContext context)) {
            return List.of();
        }
        return heldValues(context, settings);
    }

    /**
     * A held value by what it is (QF-19). The fact names a target by its template's variables only (N-INJ-1), so two new
     * projects would be one value: the target is the variables with a digest of the values the request bound to them,
     * which keeps the requester's text out of the kept record. The fact states a size or a rate with its count, so the
     * same habit would never repeat: it is the power-of-two band of the count ({@code SIZE=1024-2047}).
     */
    private static String heldValueOf(Deviation deviation, CanonicalSecurityContext context) {
        String name = deviation.dimension().name() + "=";
        if (deviation.dimension() == DeviationDimension.TARGET) {
            CanonicalSecurityContext.Resource resource = context.getResource();
            String target = resource != null
                    ? BaselineViewCalculator.target(resource.getPathFamily(), resource.getRequestPath()) : null;
            return target != null ? name + deviation.current() + "#" + AgentBaselineView.digest(target)
                    : valueOf(deviation);
        }
        if (deviation.dimension() == DeviationDimension.SIZE || deviation.dimension() == DeviationDimension.RATE) {
            Long count = leadingCount(deviation.current());
            return count != null ? name + band(count) : valueOf(deviation);
        }
        return valueOf(deviation);
    }

    /** The count a size or rate fact starts with ({@code 1,200 items}, {@code 40 requests in the last 60 min}). */
    private static Long leadingCount(String text) {
        if (text == null) {
            return null;
        }
        StringBuilder digits = new StringBuilder();
        for (char character : text.trim().toCharArray()) {
            if (Character.isDigit(character)) {
                digits.append(character);
            }
            else if (character != ',') {
                break;
            }
        }
        if (digits.isEmpty() || digits.length() > 18) {
            return null;
        }
        return Long.parseLong(digits.toString());
    }

    /** The power-of-two band of a count: {@code 0}, {@code 1-1}, {@code 2-3}, ..., {@code 1024-2047}. */
    private static String band(long count) {
        if (count <= 0) {
            return "0";
        }
        long lower = Long.highestOneBit(count);
        return lower + "-" + (lower * 2 - 1);
    }

    /**
     * The identity values of a request (time, day, network, device), compared or not, as {@link #valueOf} names them:
     * the values a verification on the request vouches for.
     */
    public static List<String> identityValues(CanonicalSecurityContext context) {
        if (context == null || context.getDecisionFacts() == null) {
            return List.of();
        }
        return context.getDecisionFacts().deviations().stream()
                .filter(deviation -> IDENTITY.contains(deviation.dimension()) && deviation.current() != null)
                .map(LearningPromotionPolicy::valueOf)
                .distinct()
                .toList();
    }

    /** Whether the class is at least the minimum in the normalised class order; SENSITIVE without a minimum. */
    private static boolean atLeast(String resourceClass, String minimum) {
        String normalized = SecuritySemanticNormalizer.normalizeResourceClass(resourceClass);
        int rank = normalized != null ? CLASS_ORDER.indexOf(normalized) : -1;
        int floor = CLASS_ORDER.indexOf(minimum != null ? minimum.trim().toUpperCase(Locale.ROOT) : "SENSITIVE");
        return rank >= 0 && floor >= 0 && rank >= floor;
    }

    /** Whether an agent sends the request, for a person or on its own (the publisher's subject kind or the subject). */
    private static boolean agentRequest(CanonicalSecurityContext context) {
        Object kind = context.getAttributes() != null ? context.getAttributes().get("executionSubjectKind") : null;
        if (SubjectKind.DELEGATED_AGENT.name().equals(String.valueOf(kind))
                || SubjectKind.AUTONOMOUS_AGENT.name().equals(String.valueOf(kind))) {
            return true;
        }
        return context.getExecutionSubject() != null
                && ExecutionSubjectTypes.AGENT_RUNTIME.equals(context.getExecutionSubject().subjectType());
    }

    /** The differences that hold back the request of the event, from the context its decision used. */
    public static List<Deviation> heldDifferences(SecurityEvent event, Settings settings) {
        if (event == null || event.getMetadata() == null
                || !(event.getMetadata().get(DECIDED_CONTEXT) instanceof CanonicalSecurityContext context)) {
            return List.of();
        }
        return heldDifferences(context, settings);
    }
}
