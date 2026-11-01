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
import io.contexa.contexacore.autonomous.baseline.AgentBaselineView;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

/**
 * W5-1 (plan L1): an allowed request on a resource of at least the configured class waits for promotion when its facts
 * name a time, day, network or device difference no record explains; the identity dimensions and the class order are
 * the ones the minimum action rule P1 counts.
 */
class LearningPromotionPolicyTest {

    private static final LearningPromotionPolicy.Settings DEFAULTS = LearningPromotionPolicy.Settings.DEFAULTS;

    @Test
    @DisplayName("an unexplained identity difference on a sensitive resource holds the request back")
    void anUnexplainedIdentityDifferenceOnASensitiveResourceIsHeld() {
        CanonicalSecurityContext context = context("SENSITIVE", unexplained(DeviationDimension.DEVICE, "Safari/18 on MAC"),
                unexplained(DeviationDimension.TARGET, "projectKey"), unexplained(DeviationDimension.TIME, "03"));

        assertThat(LearningPromotionPolicy.heldDifferences(context, DEFAULTS))
                .extracting(Deviation::dimension, Deviation::current)
                .containsExactly(tuple(DeviationDimension.DEVICE, "Safari/18 on MAC"),
                        tuple(DeviationDimension.TIME, "03"));
        assertThat(LearningPromotionPolicy.heldDifferences(event(context), DEFAULTS)).hasSize(2);
    }

    @Test
    @DisplayName("a lower class, an explained or not established difference and a non-identity difference hold nothing")
    void otherRequestsAreLearnedAtOnce() {
        Deviation network = unexplained(DeviationDimension.NETWORK, "203.0.113.0/24");

        assertThat(LearningPromotionPolicy.heldDifferences(context("NORMAL", network), DEFAULTS)).isEmpty();
        assertThat(LearningPromotionPolicy.heldDifferences(context("CRITICAL",
                deviation(DeviationDimension.NETWORK, Deviation.Explanation.EXPLAINED)), DEFAULTS)).isEmpty();
        assertThat(LearningPromotionPolicy.heldDifferences(context("CRITICAL",
                deviation(DeviationDimension.DEVICE, Deviation.Explanation.NOT_ESTABLISHED)), DEFAULTS)).isEmpty();
        assertThat(LearningPromotionPolicy.heldDifferences(context("CRITICAL",
                unexplained(DeviationDimension.SIZE, "4,831 items")), DEFAULTS)).isEmpty();
        assertThat(LearningPromotionPolicy.heldDifferences(context("CRITICAL", network), DEFAULTS)).hasSize(1);
    }

    @Test
    @DisplayName("the switch and the least class are the host's settings; without facts nothing is held")
    void theSettingsDecideAndNoFactsHoldNothing() {
        CanonicalSecurityContext sensitive = context("SENSITIVE", unexplained(DeviationDimension.DAY, "Sun"));

        assertThat(LearningPromotionPolicy.heldDifferences(sensitive,
                new LearningPromotionPolicy.Settings(false, "SENSITIVE", 2, 2, true))).isEmpty();
        assertThat(LearningPromotionPolicy.heldDifferences(sensitive,
                new LearningPromotionPolicy.Settings(true, "CRITICAL", 2, 2, true))).isEmpty();
        assertThat(LearningPromotionPolicy.heldDifferences(sensitive,
                new LearningPromotionPolicy.Settings(true, "NORMAL", 2, 2, true))).hasSize(1);
        assertThat(LearningPromotionPolicy.heldDifferences((CanonicalSecurityContext) null, DEFAULTS)).isEmpty();
        assertThat(LearningPromotionPolicy.heldDifferences(context("CRITICAL"), DEFAULTS)).isEmpty();
        assertThat(LearningPromotionPolicy.heldDifferences(SecurityEvent.builder().eventId("e").build(), DEFAULTS))
                .isEmpty();
    }

    /**
     * docs/agent A3-7: an agent's request holds back its first target, action, size, rate, network and device at any
     * resource class (not its time and day); the same differences of a person's request hold nothing below the least
     * class, and the agent rule is the host's switch.
     */
    @Test
    void anAgentsFirstValuesAreHeldBackAtAnyResourceClass() {
        Deviation[] differences = {unexplained(DeviationDimension.TARGET, "projectKey=HX-310"),
                unexplained(DeviationDimension.SIZE, "4,831 items"), unexplained(DeviationDimension.NETWORK,
                "10.60.1.0/24"), unexplained(DeviationDimension.TIME, "03"),
                deviation(DeviationDimension.ACTION, Deviation.Explanation.EXPLAINED)};
        CanonicalSecurityContext agent = context("NORMAL", differences);
        agent.getAttributes().put("executionSubjectKind", "AUTONOMOUS_AGENT");

        assertThat(LearningPromotionPolicy.heldDifferences(agent, DEFAULTS)).extracting(Deviation::dimension)
                .containsExactly(DeviationDimension.TARGET, DeviationDimension.SIZE, DeviationDimension.NETWORK);
        assertThat(LearningPromotionPolicy.heldDifferences(context("NORMAL", differences), DEFAULTS)).isEmpty();
        assertThat(LearningPromotionPolicy.heldDifferences(agent,
                new LearningPromotionPolicy.Settings(true, "SENSITIVE", 2, 2, true, false))).isEmpty();
    }

    /**
     * QF-19: a held target is named by the target the request names, as a digest of the bound values, and a held size or
     * rate by the power-of-two band of its count; every other value is named as before.
     */
    @Test
    void theHeldValuesNameATargetByItsDigestAndASizeOrRateByItsBand() {
        CanonicalSecurityContext agent = context("NORMAL", unexplained(DeviationDimension.TARGET, "projectKey"),
                unexplained(DeviationDimension.SIZE, "4,831 items"),
                unexplained(DeviationDimension.RATE, "40 requests in the last 60 min"),
                unexplained(DeviationDimension.NETWORK, "10.60.1.0/24"));
        agent.getAttributes().put("executionSubjectKind", "AUTONOMOUS_AGENT");
        agent.getResource().setPathFamily("/api/projects/{projectKey}/exports");
        agent.getResource().setRequestPath("/api/projects/HX-310/exports");

        assertThat(LearningPromotionPolicy.heldValues(agent, DEFAULTS)).containsExactly(
                "TARGET=projectKey#" + AgentBaselineView.digest("projectKey=HX-310"), "SIZE=4096-8191", "RATE=32-63",
                "NETWORK=10.60.1.0/24");
        assertThat(LearningPromotionPolicy.heldValues(context("SENSITIVE",
                unexplained(DeviationDimension.DEVICE, "Safari/18 on MAC"),
                unexplained(DeviationDimension.TIME, "03")), DEFAULTS))
                .containsExactly("DEVICE=Safari/18 on MAC", "TIME=03");
    }

    /**
     * The policy holds what the minimum action rule P1 counts (the rule source belongs to the prompt bundle, so the
     * policy keeps its own copy): for every class and dimension, the held dimensions are the ones P1 counts.
     */
    @Test
    void theHeldDimensionsAreTheOnesTheMinimumActionRuleP1Counts() {
        MinimumActionRules.Settings p1Only = new MinimumActionRules.Settings(true, 1, "SENSITIVE", false, false, "ESCALATE");
        for (String resourceClass : List.of("PUBLIC", "NORMAL", "SENSITIVE", "CRITICAL")) {
            for (DeviationDimension dimension : DeviationDimension.values()) {
                Deviation difference = unexplained(dimension, "x");
                List<DeviationDimension> counted = MinimumActionRules.evaluate(new DecisionFacts(List.of(),
                                List.of(difference), PolicySatisfaction.UNKNOWN, List.of()), resourceClass, "READ", p1Only)
                        .stream().flatMap(hit -> hit.dimensions().stream()).toList();

                assertThat(LearningPromotionPolicy.heldDifferences(context(resourceClass, difference), DEFAULTS))
                        .as(resourceClass + " " + dimension)
                        .extracting(Deviation::dimension).containsExactlyElementsOf(counted);
            }
        }
    }

    private static CanonicalSecurityContext context(String resourceClass, Deviation... deviations) {
        CanonicalSecurityContext.Resource resource = new CanonicalSecurityContext.Resource();
        resource.setResourceClass(resourceClass);
        CanonicalSecurityContext context = new CanonicalSecurityContext();
        context.setResource(resource);
        if (deviations.length > 0) {
            context.setDecisionFacts(new DecisionFacts(List.of(), List.of(deviations), PolicySatisfaction.UNKNOWN,
                    List.of()));
        }
        return context;
    }

    private static SecurityEvent event(CanonicalSecurityContext context) {
        SecurityEvent event = SecurityEvent.builder().eventId("e-1").userId("alice").build();
        event.addMetadata(LearningPromotionPolicy.DECIDED_CONTEXT, context);
        return event;
    }

    private static Deviation unexplained(DeviationDimension dimension, String current) {
        return new Deviation(dimension, current, true, true, 0, 25, null, Deviation.Explanation.UNEXPLAINED, null);
    }

    private static Deviation deviation(DeviationDimension dimension, Deviation.Explanation explanation) {
        return new Deviation(dimension, "x", true, true, 0, 25, null, explanation,
                explanation == Deviation.Explanation.EXPLAINED ? "TRAVEL-1" : null);
    }
}
