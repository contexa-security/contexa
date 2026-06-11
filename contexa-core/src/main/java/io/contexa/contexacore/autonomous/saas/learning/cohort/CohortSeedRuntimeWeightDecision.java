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
package io.contexa.contexacore.autonomous.saas.learning.cohort;

import io.contexa.contexacore.autonomous.saas.dto.BaselineSeedSnapshot;

import java.util.List;

/**
 * Runtime weight decision for cohort baseline seed usage.
 */
public record CohortSeedRuntimeWeightDecision(
        BaselineSeedSnapshot seedSnapshot,
        boolean seedAllowed,
        double runtimeWeight,
        CohortSeedRuntimeWeightState weightState,
        List<String> policyFacts) {

    public CohortSeedRuntimeWeightDecision {
        runtimeWeight = Double.isFinite(runtimeWeight) ? Math.max(0.0d, Math.min(1.0d, runtimeWeight)) : 0.0d;
        weightState = weightState == null ? CohortSeedRuntimeWeightState.UNAVAILABLE : weightState;
        policyFacts = policyFacts == null ? List.of() : List.copyOf(policyFacts);
    }
}