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