package io.contexa.contexacore.std.components.prompt;

import java.util.List;

public final class PromptTokenEstimatorRegistry {

    private static final PromptTokenEstimatorRegistry DEFAULT =
            new PromptTokenEstimatorRegistry(List.of(
                    new UsageCalibratedPromptTokenEstimator(),
                    new ModelAwarePromptTokenEstimator()));

    private final List<PromptTokenEstimator> estimators;

    public PromptTokenEstimatorRegistry(List<PromptTokenEstimator> estimators) {
        this.estimators = estimators == null || estimators.isEmpty()
                ? List.of(new UsageCalibratedPromptTokenEstimator(), new ModelAwarePromptTokenEstimator())
                : List.copyOf(estimators);
    }

    public static PromptTokenEstimatorRegistry defaultRegistry() {
        return DEFAULT;
    }

    public PromptTokenEstimator resolve(String modelHint) {
        for (PromptTokenEstimator estimator : estimators) {
            if (estimator.supports(modelHint)) {
                return estimator;
            }
        }
        return estimators.get(0);
    }
}
