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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** W4-4: the minimum-action rules P1-P3 read the structured decision facts (dictionary 6, plan 7). */
class MinimumActionRulesTest {

    private static final MinimumActionRules.Settings DEFAULTS = MinimumActionRules.Settings.DEFAULTS;

    @Test
    @DisplayName("P1: two unexplained identity differences on a sensitive resource ask for at least a challenge")
    void twoUnexplainedIdentityDifferencesOnASensitiveResourceHitP1() {
        DecisionFacts facts = facts(PolicySatisfaction.UNKNOWN, unexplained(DeviationDimension.TIME),
                unexplained(DeviationDimension.NETWORK), unexplained(DeviationDimension.TARGET));

        List<MinimumActionRules.Hit> hits = MinimumActionRules.evaluate(facts, "SENSITIVE", "READ", DEFAULTS);

        assertThat(hits).extracting(MinimumActionRules.Hit::rule)
                .containsExactly(MinimumActionRules.Rule.P1_IDENTITY_DEVIATION);
        assertThat(hits.get(0).requiredAction()).isEqualTo("CHALLENGE");
        assertThat(hits.get(0).dimensions()).containsExactly(DeviationDimension.TIME, DeviationDimension.NETWORK);
        assertThat(MinimumActionRules.violatedBy("ALLOW", hits)).isTrue();
        assertThat(MinimumActionRules.violatedBy("CHALLENGE", hits)).isFalse();
        assertThat(MinimumActionRules.violatedBy("BLOCK", hits)).isFalse();
    }

    @Test
    @DisplayName("P1 counts no explained, not established or uncompared difference, and needs a sensitive class")
    void p1CountsOnlyUnexplainedDifferencesOnASensitiveResource() {
        DecisionFacts travel = facts(PolicySatisfaction.UNKNOWN, unexplained(DeviationDimension.TIME),
                deviation(DeviationDimension.NETWORK, Deviation.Explanation.EXPLAINED));
        DecisionFacts provisional = facts(PolicySatisfaction.UNKNOWN,
                deviation(DeviationDimension.TIME, Deviation.Explanation.NOT_ESTABLISHED),
                deviation(DeviationDimension.DAY, Deviation.Explanation.NOT_ESTABLISHED));
        DecisionFacts two = facts(PolicySatisfaction.UNKNOWN, unexplained(DeviationDimension.TIME),
                unexplained(DeviationDimension.DAY));

        assertThat(MinimumActionRules.evaluate(travel, "CRITICAL", "READ", DEFAULTS)).isEmpty();
        assertThat(MinimumActionRules.evaluate(provisional, "CRITICAL", "READ", DEFAULTS)).isEmpty();
        assertThat(MinimumActionRules.evaluate(two, "NORMAL", "READ", DEFAULTS)).isEmpty();
        assertThat(MinimumActionRules.evaluate(two, "CRITICAL", "READ", DEFAULTS)).hasSize(1);
        assertThat(MinimumActionRules.evaluate(two, "CRITICAL", "READ",
                new MinimumActionRules.Settings(true, 3, "SENSITIVE", true, true, "CHALLENGE"))).isEmpty();
        assertThat(MinimumActionRules.evaluate(two, "CRITICAL", "READ",
                new MinimumActionRules.Settings(false, 2, "SENSITIVE", true, true, "CHALLENGE"))).isEmpty();
    }

    @Test
    @DisplayName("P2: an export of a sensitive resource from an unexplained device or network")
    void anExportFromAnUnexplainedDeviceHitsP2() {
        DecisionFacts device = facts(PolicySatisfaction.UNKNOWN, unexplained(DeviationDimension.DEVICE));

        assertThat(MinimumActionRules.evaluate(device, "SENSITIVE", "EXPORT", DEFAULTS))
                .extracting(MinimumActionRules.Hit::rule)
                .containsExactly(MinimumActionRules.Rule.P2_NEW_DEVICE_OR_NETWORK_EXPORT);
        assertThat(MinimumActionRules.evaluate(device, "SENSITIVE", "READ", DEFAULTS)).isEmpty();
        assertThat(MinimumActionRules.evaluate(device, "NORMAL", "EXPORT", DEFAULTS)).isEmpty();
        assertThat(MinimumActionRules.evaluate(device, "CRITICAL", "EXPORT",
                new MinimumActionRules.Settings(true, 2, "SENSITIVE", false, true, "CHALLENGE"))).isEmpty();
    }

    @Test
    @DisplayName("P3: a policy the records do not satisfy; an unknown policy is no hit")
    void anUnsatisfiedPolicyHitsP3() {
        PolicySatisfaction no = new PolicySatisfaction(false, null, List.of(), "no approval", List.of());
        PolicySatisfaction yes = new PolicySatisfaction(true, null, List.of(), "assigned", List.of());

        assertThat(MinimumActionRules.evaluate(facts(no), "NORMAL", "READ", DEFAULTS))
                .extracting(MinimumActionRules.Hit::rule)
                .containsExactly(MinimumActionRules.Rule.P3_POLICY_NOT_SATISFIED);
        assertThat(MinimumActionRules.evaluate(facts(yes), "NORMAL", "READ", DEFAULTS)).isEmpty();
        assertThat(MinimumActionRules.evaluate(facts(PolicySatisfaction.UNKNOWN), "NORMAL", "READ", DEFAULTS)).isEmpty();
        assertThat(MinimumActionRules.evaluate(facts(no), "NORMAL", "READ",
                new MinimumActionRules.Settings(true, 2, "SENSITIVE", true, false, "CHALLENGE"))).isEmpty();
    }

    /**
     * Q-87 (N-P3-1): a policy the records do not satisfy asks for a review: a verification of the user does not supply
     * the missing record, so a challenge is weaker than P3, while P1 keeps the challenge.
     */
    @Test
    void anUnsatisfiedPolicyAsksForAReviewAndAChallengeIsWeaker() {
        PolicySatisfaction no = new PolicySatisfaction(false, null, List.of(), "no approval", List.of());
        List<MinimumActionRules.Hit> p3 = MinimumActionRules.evaluate(facts(no), "NORMAL", "READ", DEFAULTS);
        List<MinimumActionRules.Hit> p1 = MinimumActionRules.evaluate(facts(PolicySatisfaction.UNKNOWN,
                unexplained(DeviationDimension.TIME), unexplained(DeviationDimension.NETWORK)), "SENSITIVE", "READ", DEFAULTS);

        assertThat(p3.get(0).requiredAction()).isEqualTo("ESCALATE");
        assertThat(MinimumActionRules.violatedBy("CHALLENGE", p3)).isTrue();
        assertThat(MinimumActionRules.violatedBy("ESCALATE", p3)).isFalse();
        assertThat(MinimumActionRules.violatedBy("BLOCK", p3)).isFalse();
        assertThat(p1.get(0).requiredAction()).isEqualTo("CHALLENGE");
        assertThat(MinimumActionRules.violatedBy("CHALLENGE", p1)).isFalse();
    }

    /**
     * Q-87 (N-P3-1, N-CONF-1): the host may name CHALLENGE or ESCALATE as the P3 floor. A floor of BLOCK could never
     * be met, as a BLOCK needs decisive block evidence the policy facts are not; it, and any other value, is refused
     * when the settings are made, instead of silently becoming a review.
     */
    @Test
    void theHostNamesAP3FloorThePolicyFactsCanMeetAndAnyOtherValueIsRefused() {
        PolicySatisfaction no = new PolicySatisfaction(false, null, List.of(), "no approval", List.of());

        assertThat(floorOfP3(no, "CHALLENGE")).isEqualTo("CHALLENGE");
        assertThat(floorOfP3(no, " escalate ")).isEqualTo("ESCALATE");
        for (String refused : new String[]{"BLOCK", " block ", "ALLOW", "REVIEW", "", null}) {
            assertThatThrownBy(() -> new MinimumActionRules.Settings(true, 2, "SENSITIVE", true, true, refused))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("contexa.security.zerotrust.minimum-action.policy-satisfaction.action")
                    .hasMessageContaining("CHALLENGE or ESCALATE");
        }
    }

    private static String floorOfP3(PolicySatisfaction policy, String action) {
        return MinimumActionRules.evaluate(facts(policy), "NORMAL", "READ",
                new MinimumActionRules.Settings(true, 2, "SENSITIVE", true, true, action)).get(0).requiredAction();
    }

    @Test
    @DisplayName("the rules name the reason codes of the output contract")
    void theRulesNameTheReasonCodes() {
        assertThat(MinimumActionRules.Rule.P1_IDENTITY_DEVIATION.code()).isEqualTo("MIN_P1_IDENTITY_DEVIATION");
        assertThat(MinimumActionRules.Rule.P3_POLICY_NOT_SATISFIED.code()).isEqualTo("MIN_P3_POLICY_NOT_SATISFIED");
    }

    private static DecisionFacts facts(PolicySatisfaction policy, Deviation... deviations) {
        return new DecisionFacts(List.of(), List.of(deviations), policy, List.of());
    }

    private static Deviation unexplained(DeviationDimension dimension) {
        return deviation(dimension, Deviation.Explanation.UNEXPLAINED);
    }

    private static Deviation deviation(DeviationDimension dimension, Deviation.Explanation explanation) {
        return new Deviation(dimension, "x", true, true, 0, 10, "y", explanation,
                explanation == Deviation.Explanation.EXPLAINED ? "TRAVEL-1" : null);
    }
}
