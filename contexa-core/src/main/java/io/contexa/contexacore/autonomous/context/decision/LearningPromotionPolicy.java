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
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;

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

    /** The promotion switch and limits (contexa.security.zerotrust.baseline.promotion.*). */
    public record Settings(boolean enabled, String minResourceClass, int minObservations, int minDistinctDays,
                           boolean verifiedPromotes) {

        public static final Settings DEFAULTS = new Settings(true, "SENSITIVE", 2, 2, true);
    }

    private LearningPromotionPolicy() {
    }

    /** The differences that hold the request back; empty when the request is learned at once. */
    public static List<Deviation> heldDifferences(CanonicalSecurityContext context, Settings settings) {
        Settings rules = settings != null ? settings : Settings.DEFAULTS;
        if (!rules.enabled() || context == null || context.getDecisionFacts() == null) {
            return List.of();
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

    /** The differences that hold back the request of the event, from the context its decision used. */
    public static List<Deviation> heldDifferences(SecurityEvent event, Settings settings) {
        if (event == null || event.getMetadata() == null
                || !(event.getMetadata().get(DECIDED_CONTEXT) instanceof CanonicalSecurityContext context)) {
            return List.of();
        }
        return heldDifferences(context, settings);
    }
}
