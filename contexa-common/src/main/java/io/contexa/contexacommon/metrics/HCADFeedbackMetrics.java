package io.contexa.contexacommon.metrics;


public interface HCADFeedbackMetrics {

    
    void recordAnalysis(long durationNanos, double finalSimilarity, boolean isAnomaly);

    
    void recordLayerContributions(
        double threatSearchContribution,
        double baselineContribution,
        double anomalyContribution,
        double correlationContribution
    );

    
    void recordBaselineUpdate();

    
    void recordThresholdAdjustment();

    
    void recordFeedbackProcessing(long durationNanos);
}
