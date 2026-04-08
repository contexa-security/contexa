package io.contexa.contexacore.autonomous.saas.learning.cohort;

import io.contexa.contexacore.autonomous.saas.dto.BaselineSeedSnapshot;

public interface CohortSeedRuntimeWeightPolicy {

    CohortSeedRuntimeWeightDecision evaluate(
            BaselineSeedSnapshot seedSnapshot,
            boolean personalBaselineEstablished,
            boolean organizationBaselineEstablished);
}