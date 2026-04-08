package io.contexa.contexacore.autonomous.saas.learning.cohort;

import io.contexa.contexacore.autonomous.saas.dto.BaselineSeedSnapshot;

import java.util.List;
import java.util.Locale;

/**
 * Degrades cohort seed influence as local baselines become established.
 */
public class DefaultCohortSeedRuntimeWeightPolicy implements CohortSeedRuntimeWeightPolicy {

    @Override
    public CohortSeedRuntimeWeightDecision evaluate(
            BaselineSeedSnapshot seedSnapshot,
            boolean personalBaselineEstablished,
            boolean organizationBaselineEstablished) {
        if (seedSnapshot == null || !seedSnapshot.featureEnabled() || !seedSnapshot.seedAvailable()) {
            return new CohortSeedRuntimeWeightDecision(
                    null,
                    false,
                    0.0d,
                    CohortSeedRuntimeWeightState.UNAVAILABLE,
                    List.of("Cohort baseline seed is unavailable, disabled, or not marked seedAvailable."));
        }
        if (personalBaselineEstablished && organizationBaselineEstablished) {
            return decision(seedSnapshot, 0.15d, CohortSeedRuntimeWeightState.DEGRADED_ESTABLISHED_BASELINES,
                    "Both personal and organization baselines are established; cohort seed remains only as very low-priority support.");
        }
        if (organizationBaselineEstablished) {
            return decision(seedSnapshot, 0.30d, CohortSeedRuntimeWeightState.DEGRADED_ORGANIZATION_BASELINE,
                    "Organization baseline is established; cohort seed is degraded to missing-dimension support.");
        }
        if (personalBaselineEstablished) {
            return decision(seedSnapshot, 0.50d, CohortSeedRuntimeWeightState.DEGRADED_PERSONAL_BASELINE,
                    "Personal baseline is established; cohort seed is degraded while organization baseline continues to mature.");
        }
        return decision(seedSnapshot, 1.0d, CohortSeedRuntimeWeightState.FULL_COLD_START_SUPPORT,
                "Local baselines are immature; cohort seed can be used as cold-start support context.");
    }

    private CohortSeedRuntimeWeightDecision decision(
            BaselineSeedSnapshot seedSnapshot,
            double runtimeWeight,
            CohortSeedRuntimeWeightState state,
            String summary) {
        return new CohortSeedRuntimeWeightDecision(
                seedSnapshot,
                true,
                runtimeWeight,
                state,
                List.of(
                        summary,
                        String.format(Locale.ROOT,
                                "Runtime weight %.2f applies to cohort %s with %d cohort tenants and %d sampled user baselines.",
                                runtimeWeight,
                                seedSnapshot.cohortLabel() == null ? "UNSPECIFIED" : seedSnapshot.cohortLabel(),
                                seedSnapshot.cohortTenantCount(),
                                seedSnapshot.sampleUserBaselineCount())));
    }
}