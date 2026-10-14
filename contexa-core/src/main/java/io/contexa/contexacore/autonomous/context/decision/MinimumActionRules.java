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

import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * The minimum-action rules of the security decision (plan 7, dictionary 6, W4-4): the least action the structured
 * decision facts ask for. A rule is a floor, never a reason to go higher; the code decides no action itself. Only a
 * difference no record explains counts; a difference against a baseline not established, or not compared, is unknown.
 */
public final class MinimumActionRules {

    /** The identity dimensions P1 counts; the device is one dimension. */
    private static final Set<DeviationDimension> IDENTITY = Set.of(
            DeviationDimension.TIME, DeviationDimension.DAY, DeviationDimension.NETWORK, DeviationDimension.DEVICE);
    private static final Set<DeviationDimension> DEVICE_OR_NETWORK = Set.of(
            DeviationDimension.DEVICE, DeviationDimension.NETWORK);
    /** The normalised resource classes from the least to the most sensitive (SecuritySemanticNormalizer). */
    private static final List<String> CLASS_ORDER = List.of("PUBLIC", "NORMAL", "SENSITIVE", "CRITICAL");
    private static final String CHALLENGE = "CHALLENGE";

    public enum Rule {
        P1_IDENTITY_DEVIATION("MIN_P1_IDENTITY_DEVIATION"),
        P2_NEW_DEVICE_OR_NETWORK_EXPORT("MIN_P2_NEW_DEVICE_OR_NETWORK_EXPORT"),
        P3_POLICY_NOT_SATISFIED("MIN_P3_POLICY_NOT_SATISFIED");

        private final String code;

        Rule(String code) {
            this.code = code;
        }

        /** The reason code of the output contract that cites this rule. */
        public String code() {
            return code;
        }
    }

    /** A rule the facts meet, the least action it asks for and the differences it counted. */
    public record Hit(Rule rule, String requiredAction, List<DeviationDimension> dimensions) {

        public Hit {
            dimensions = List.copyOf(dimensions);
        }
    }

    /** The rule switches and limits (contexa.security.zerotrust.minimum-action.*). */
    public record Settings(boolean identityEnabled, int identityMinDeviations, String identityMinResourceClass,
                           boolean newDeviceExportEnabled, boolean policySatisfactionEnabled) {

        public static final Settings DEFAULTS = new Settings(true, 2, "SENSITIVE", true, true);
    }

    private MinimumActionRules() {
    }

    /** The rules the facts of a request meet, in rule order; empty without facts. */
    public static List<Hit> evaluate(DecisionFacts facts, String resourceClass, String actionFamily, Settings settings) {
        if (facts == null) {
            return List.of();
        }
        Settings rules = settings != null ? settings : Settings.DEFAULTS;
        List<DeviationDimension> unexplained = facts.unexplained().stream().map(Deviation::dimension).toList();
        List<Hit> hits = new ArrayList<>();
        List<DeviationDimension> identity = unexplained.stream().filter(IDENTITY::contains).distinct().toList();
        if (rules.identityEnabled() && atLeast(resourceClass, rules.identityMinResourceClass())
                && identity.size() >= rules.identityMinDeviations()) {
            hits.add(new Hit(Rule.P1_IDENTITY_DEVIATION, CHALLENGE, identity));
        }
        List<DeviationDimension> deviceOrNetwork = unexplained.stream().filter(DEVICE_OR_NETWORK::contains).distinct()
                .toList();
        if (rules.newDeviceExportEnabled() && atLeast(resourceClass, "SENSITIVE") && isExport(actionFamily)
                && !deviceOrNetwork.isEmpty()) {
            hits.add(new Hit(Rule.P2_NEW_DEVICE_OR_NETWORK_EXPORT, CHALLENGE, deviceOrNetwork));
        }
        if (rules.policySatisfactionEnabled() && Boolean.FALSE.equals(facts.policy().satisfied())) {
            hits.add(new Hit(Rule.P3_POLICY_NOT_SATISFIED, CHALLENGE, List.of()));
        }
        return List.copyOf(hits);
    }

    /** Whether the action is weaker than a rule asks for: only ALLOW is below a challenge. */
    public static boolean violatedBy(String action, List<Hit> hits) {
        return hits != null && !hits.isEmpty() && action != null
                && "ALLOW".equals(action.trim().toUpperCase(Locale.ROOT));
    }

    private static boolean atLeast(String resourceClass, String minimum) {
        String normalized = SecuritySemanticNormalizer.normalizeResourceClass(resourceClass);
        int rank = normalized != null ? CLASS_ORDER.indexOf(normalized) : -1;
        int floor = CLASS_ORDER.indexOf(minimum != null ? minimum.trim().toUpperCase(Locale.ROOT) : "SENSITIVE");
        return rank >= 0 && floor >= 0 && rank >= floor;
    }

    private static boolean isExport(String actionFamily) {
        return actionFamily != null && "EXPORT".equals(actionFamily.trim().toUpperCase(Locale.ROOT));
    }
}
