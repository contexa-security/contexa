package io.contexa.contexacore.verification.runtime.prompt;

public interface FinalPromptMetricEvaluator {

    String metricCode();

    FinalPromptMetricResult evaluate(FinalPromptMetricEvaluationContext context);
}
