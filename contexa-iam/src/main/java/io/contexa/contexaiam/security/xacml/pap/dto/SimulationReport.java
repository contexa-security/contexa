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
package io.contexa.contexaiam.security.xacml.pap.dto;

import java.util.List;

public record SimulationReport(
        List<SimulationResult> results,
        SimulationSummary summary) {

    public record SimulationResult(
            SimulationTestCase testCase,
            String username,
            DecisionDetail currentResult,
            DecisionDetail newResult,
            boolean changed,
            String changeType) {
    }

    /**
     * Simulated decision of one test case.
     *
     * @param decision                ALLOW or DENY as the enforcement point would decide
     * @param matchedPolicyId         the policy whose decision was returned, {@code null} when none
     * @param matchedPolicyName       name of that policy
     * @param matchedExpression       condition expression of that policy as the enforcement point builds it
     * @param userAuthorities         authorities of the simulated user
     * @param combiningAlgorithm      the combining algorithm that was applied
     * @param noPolicyDecision        the no-matching-policy decision configured for the target type
     * @param noPolicyDecisionApplied whether the decision is that no-matching-policy decision
     */
    public record DecisionDetail(
            String decision,
            Long matchedPolicyId,
            String matchedPolicyName,
            String matchedExpression,
            List<String> userAuthorities,
            String combiningAlgorithm,
            String noPolicyDecision,
            boolean noPolicyDecisionApplied) {
    }

    public record SimulationSummary(
            int unchanged,
            int allowToDeny,
            int denyToAllow,
            int otherChanges) {
    }
}
