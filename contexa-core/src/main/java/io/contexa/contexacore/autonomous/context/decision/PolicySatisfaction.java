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

import java.util.List;

/**
 * Whether the company's policies for the request are satisfied at the request time (W2-5).
 *
 * @param satisfied   true when every policy is satisfied, false when one is not, null when the host stated no policy,
 *                    a policy the engine cannot read, or a fact a policy needs is not known (P2 correction 3)
 * @param reason      why the first unsatisfied policy is not satisfied, null otherwise
 * @param recordIds   the records that satisfy or fail the policies ({@code APR-...}); an exception names no record
 * @param detail      the satisfaction in words: {@code approval APR-... decided 20 min after this request}
 * @param policyIds   the policies weighed, in the host's order
 */
public record PolicySatisfaction(
        Boolean satisfied,
        PolicyReason reason,
        List<String> recordIds,
        String detail,
        List<String> policyIds) {

    public static final PolicySatisfaction UNKNOWN = new PolicySatisfaction(null, null, List.of(), null, List.of());

    public PolicySatisfaction {
        recordIds = recordIds == null ? List.of() : List.copyOf(recordIds);
        policyIds = policyIds == null ? List.of() : List.copyOf(policyIds);
    }

    /** The fact as the prompt states it: {@code no — approval APR-... decided 20 min after this request}. */
    public String describe() {
        if (satisfied == null) {
            return detail != null ? "unknown — " + detail : null;
        }
        return (satisfied ? "yes" : "no") + (detail != null ? " — " + detail : "");
    }
}
