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
package io.contexa.contexacore.std.components.prompt.quality;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.Objects;

/**
 * The decision input of a labelled case (plan 3.2), in the form the replay of a sealed decision reads: structured
 * values, not prompt text, so the case is drawn again when the form of the prompt changes. The values are read only.
 *
 * @param canonicalContext     the canonical security context
 * @param requestFacts         the facts of the request
 * @param authState            the authentication state
 * @param baselineSnapshot     the summary of the baselines
 * @param ragResults           the past records the search returned, with its counts and states
 * @param pastDeniedDecisions  the past decisions that did not allow, when the request had any, else null
 * @param personalBaseline     the baseline of the user at the time of the decision, or null
 * @param organizationBaseline the baseline of the organization at the time of the decision, or null
 */
public record QualityCaseInput(JsonNode canonicalContext, JsonNode requestFacts, JsonNode authState,
                               JsonNode baselineSnapshot, JsonNode ragResults, JsonNode pastDeniedDecisions,
                               JsonNode personalBaseline, JsonNode organizationBaseline) {

    public QualityCaseInput {
        Objects.requireNonNull(canonicalContext, "canonicalContext");
        Objects.requireNonNull(requestFacts, "requestFacts");
        Objects.requireNonNull(authState, "authState");
        Objects.requireNonNull(baselineSnapshot, "baselineSnapshot");
        Objects.requireNonNull(ragResults, "ragResults");
        if (!canonicalContext.isObject()) {
            throw new IllegalArgumentException("A labelled case needs its canonical context");
        }
        pastDeniedDecisions = absent(pastDeniedDecisions) ? null : pastDeniedDecisions;
        personalBaseline = absent(personalBaseline) ? null : personalBaseline;
        organizationBaseline = absent(organizationBaseline) ? null : organizationBaseline;
    }

    private static boolean absent(JsonNode node) {
        return node == null || node.isNull() || node.isMissingNode();
    }
}
