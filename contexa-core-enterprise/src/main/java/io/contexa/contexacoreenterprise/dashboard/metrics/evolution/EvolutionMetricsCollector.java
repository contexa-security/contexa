package io.contexa.contexacoreenterprise.dashboard.metrics.evolution;

import io.contexa.contexacoreenterprise.dashboard.api.DomainMetrics;
import io.contexa.contexacoreenterprise.dashboard.api.EventRecorder;
import io.contexa.contexacoreenterprise.dashboard.metrics.unified.UnifiedSecurityMetricsCollector;
import io.micrometer.core.instrument.*;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@RequiredArgsConstructor
public class EvolutionMetricsCollector implements DomainMetrics, EventRecorder {

    private final MeterRegistry meterRegistry;
    private final UnifiedSecurityMetricsCollector unifiedMetrics;

    private Counter proposalCreatedCounter;
    private Counter proposalApprovedCounter;
    private Counter proposalRejectedCounter;
    private Timer proposalGenerationTimer;

    private final AtomicLong totalProposals = new AtomicLong(0);
    private final AtomicLong approvedProposals = new AtomicLong(0);
    private final AtomicLong highConfidenceProposals = new AtomicLong(0);
    private DistributionSummary confidenceScoreDistribution;

    private Timer aiCallDurationTimer;
    private Counter aiCallSuccessCounter;
    private Counter aiCallFailureCounter;
    private Counter spelExtractionSuccessCounter;
    private Counter spelExtractionFailureCounter;

    private Counter vectorStoreDocumentsStoredCounter;
    private DistributionSummary similarCasesFoundDistribution;

    private Counter incidentsProcessedCounter;
    private Counter proposalsGeneratedCounter;
    private Counter dailyLimitReachedCounter;
    private DistributionSummary learningConfidenceDistribution;

    private Counter baselineUpdatesCounter;
    private Counter statisticalOutliersCounter;
    private Counter suspiciousContextsFilteredCounter;
    private DistributionSummary baselineConfidenceDistribution;

    @PostConstruct
    public void initialize() {
        
        initProposalLifecycleMetrics();
        initLearningQualityMetrics();
        initAIModelMetrics();
        initVectorStoreMetrics();
        initLearningCoordinatorMetrics();
        initHCADMetrics();

        unifiedMetrics.updateDomainHealth("evolution", 1.0);

            }

    private void initProposalLifecycleMetrics() {
        proposalCreatedCounter = Counter.builder("evolution.proposal.created")
                .description("Total policy proposals created")
                .register(meterRegistry);

        proposalApprovedCounter = Counter.builder("evolution.proposal.approved")
                .description("Total policy proposals approved")
                .register(meterRegistry);

        proposalRejectedCounter = Counter.builder("evolution.proposal.rejected")
                .description("Total policy proposals rejected")
                .register(meterRegistry);

        proposalGenerationTimer = Timer.builder("evolution.proposal.generation.duration")
                .description("Policy proposal generation time")
                .publishPercentiles(0.5, 0.95, 0.99)
                .register(meterRegistry);

        Gauge.builder("evolution.proposal.auto_approval.rate", this,
                        collector -> collector.calculateAutoApprovalRate())
                .description("Automatic policy approval rate")
                .register(meterRegistry);
    }

    private void initLearningQualityMetrics() {
        confidenceScoreDistribution = DistributionSummary.builder("evolution.confidence.score")
                .description("Policy proposal confidence score distribution")
                .publishPercentiles(0.5, 0.75, 0.95)
                .register(meterRegistry);

        learningConfidenceDistribution = DistributionSummary.builder("evolution.learning.confidence")
                .description("Learning metadata confidence score distribution")
                .publishPercentiles(0.5, 0.75, 0.95)
                .register(meterRegistry);

        Gauge.builder("evolution.proposal.high_confidence.ratio", this,
                        collector -> collector.calculateHighConfidenceRatio())
                .description("Ratio of high confidence proposals (>0.8)")
                .register(meterRegistry);
    }

    private void initAIModelMetrics() {
        aiCallDurationTimer = Timer.builder("evolution.ai.call.duration")
                .description("AI model call duration")
                .publishPercentiles(0.5, 0.95, 0.99)
                .register(meterRegistry);

        aiCallSuccessCounter = Counter.builder("evolution.ai.call.result")
                .tag("result", "success")
                .description("AI model call success count")
                .register(meterRegistry);

        aiCallFailureCounter = Counter.builder("evolution.ai.call.result")
                .tag("result", "failure")
                .description("AI model call failure count")
                .register(meterRegistry);

        spelExtractionSuccessCounter = Counter.builder("evolution.spel.extraction")
                .tag("result", "success")
                .description("SpEL expression extraction success count")
                .register(meterRegistry);

        spelExtractionFailureCounter = Counter.builder("evolution.spel.extraction")
                .tag("result", "failure")
                .description("SpEL expression extraction failure count")
                .register(meterRegistry);

        Gauge.builder("evolution.ai.success.rate", this,
                        collector -> collector.calculateAISuccessRate())
                .description("AI model call success rate")
                .register(meterRegistry);
    }

    private void initVectorStoreMetrics() {
        vectorStoreDocumentsStoredCounter = Counter.builder("evolution.vector.documents.stored")
                .description("Total learning documents stored in vector store")
                .register(meterRegistry);

        similarCasesFoundDistribution = DistributionSummary.builder("evolution.vector.similar_cases.count")
                .description("Number of similar cases found in vector search")
                .publishPercentiles(0.5, 0.95)
                .register(meterRegistry);
    }

    private void initLearningCoordinatorMetrics() {
        incidentsProcessedCounter = Counter.builder("evolution.coordinator.incidents.processed")
                .description("Total incidents processed by learning coordinator")
                .register(meterRegistry);

        proposalsGeneratedCounter = Counter.builder("evolution.coordinator.proposals.generated")
                .description("Total proposals generated by learning coordinator")
                .register(meterRegistry);

        dailyLimitReachedCounter = Counter.builder("evolution.coordinator.daily_limit.reached")
                .description("Number of times daily proposal limit was reached")
                .register(meterRegistry);
    }

    private void initHCADMetrics() {
        baselineUpdatesCounter = Counter.builder("evolution.hcad.baseline.updates")
                .description("HCAD baseline updates count")
                .register(meterRegistry);

        statisticalOutliersCounter = Counter.builder("evolution.hcad.statistical.outliers")
                .description("Statistical outliers detected in HCAD")
                .register(meterRegistry);

        suspiciousContextsFilteredCounter = Counter.builder("evolution.hcad.suspicious.contexts.filtered")
                .description("Suspicious contexts filtered to prevent baseline pollution")
                .register(meterRegistry);

        baselineConfidenceDistribution = DistributionSummary.builder("evolution.hcad.baseline.confidence")
                .description("HCAD baseline confidence score distribution")
                .publishPercentiles(0.5, 0.75, 0.95)
                .register(meterRegistry);
    }

    public void recordProposalCreation(long durationMillis, String proposalType, String riskLevel, double confidenceScore) {
        proposalCreatedCounter.increment();
        totalProposals.incrementAndGet();
        proposalGenerationTimer.record(java.time.Duration.ofMillis(durationMillis));
        confidenceScoreDistribution.record(confidenceScore);

        if (confidenceScore > 0.8) {
            highConfidenceProposals.incrementAndGet();
        }

        Counter.builder("evolution.proposal.created.detailed")
                .tag("proposal_type", proposalType)
                .tag("risk_level", riskLevel)
                .tag("confidence_bucket", getConfidenceBucket(confidenceScore))
                .register(meterRegistry)
                .increment();

        unifiedMetrics.recordSecurityEvent("evolution", "proposal_created");

        Map<String, Object> eventMetadata = new HashMap<>();
        eventMetadata.put("source", "evolution");
        eventMetadata.put("event_type", "proposal_created");
        eventMetadata.put("proposal_type", proposalType);
        eventMetadata.put("risk_level", riskLevel);
        eventMetadata.put("confidence_score", confidenceScore);
        unifiedMetrics.recordEvent("security_event", eventMetadata);

        updateEvolutionHealth();
    }

    public void recordProposalApproval(String approvalMethod) {
        proposalApprovedCounter.increment();
        approvedProposals.incrementAndGet();

        Counter.builder("evolution.proposal.approved.by_method")
                .tag("method", approvalMethod)
                .register(meterRegistry)
                .increment();

        unifiedMetrics.recordSecurityEvent("evolution", "proposal_approved");
    }

    public void recordProposalRejection(String rejectionReason) {
        proposalRejectedCounter.increment();

        Counter.builder("evolution.proposal.rejected.by_reason")
                .tag("reason", rejectionReason != null ? rejectionReason : "unknown")
                .register(meterRegistry)
                .increment();

        unifiedMetrics.recordSecurityEvent("evolution", "proposal_rejected");
        updateEvolutionHealth();
    }

    public void recordAICall(long durationMillis, String model, boolean success) {
        aiCallDurationTimer.record(java.time.Duration.ofMillis(durationMillis));

        if (success) {
            aiCallSuccessCounter.increment();
        } else {
            aiCallFailureCounter.increment();
        }

        Timer.builder("evolution.ai.call.duration.by_model")
                .tag("model", model)
                .tag("result", success ? "success" : "failure")
                .register(meterRegistry)
                .record(java.time.Duration.ofMillis(durationMillis));
    }

    public void recordSpelExtraction(String extractionMethod, boolean success) {
        if (success) {
            spelExtractionSuccessCounter.increment();
        } else {
            spelExtractionFailureCounter.increment();
        }

        Counter.builder("evolution.spel.extraction.by_method")
                .tag("method", extractionMethod)
                .tag("result", success ? "success" : "failure")
                .register(meterRegistry)
                .increment();
    }

    public void recordVectorStoreDocument(String learningType) {
        vectorStoreDocumentsStoredCounter.increment();

        Counter.builder("evolution.vector.documents.by_type")
                .tag("learning_type", learningType)
                .register(meterRegistry)
                .increment();
    }

    public void recordSimilarCasesFound(int similarCasesCount) {
        similarCasesFoundDistribution.record(similarCasesCount);
    }

    public void recordIncidentProcessed(String severity, boolean successful, String learningType) {
        incidentsProcessedCounter.increment();

        Counter.builder("evolution.coordinator.incidents.by_severity")
                .tag("severity", severity)
                .tag("successful", String.valueOf(successful))
                .tag("learning_type", learningType)
                .register(meterRegistry)
                .increment();
    }

    public void recordCoordinatorProposalGenerated(String triggerType) {
        proposalsGeneratedCounter.increment();

        Counter.builder("evolution.coordinator.proposals.by_trigger")
                .tag("trigger_type", triggerType)
                .register(meterRegistry)
                .increment();
    }

    public void recordDailyLimitReached() {
        dailyLimitReachedCounter.increment();
    }

    public void recordLearningConfidence(double confidenceScore) {
        learningConfidenceDistribution.record(confidenceScore);
    }

    public void recordHCADBaselineUpdate(String phase, String decision) {
        baselineUpdatesCounter.increment();

        Counter.builder("evolution.hcad.baseline.updates.detailed")
                .tag("phase", phase)
                .tag("decision", decision)
                .register(meterRegistry)
                .increment();
    }

    public void recordHCADStatisticalOutlier(double zScore) {
        statisticalOutliersCounter.increment();

        String zScoreBucket;
        if (zScore >= 5.0) {
            zScoreBucket = "5+";
        } else if (zScore >= 4.0) {
            zScoreBucket = "4-5";
        } else {
            zScoreBucket = "3-4";
        }

        Counter.builder("evolution.hcad.outliers.by_zscore")
                .tag("z_score_bucket", zScoreBucket)
                .register(meterRegistry)
                .increment();
    }

    public void recordHCADSuspiciousContextFiltered(String reason) {
        suspiciousContextsFilteredCounter.increment();

        Counter.builder("evolution.hcad.suspicious.by_reason")
                .tag("reason", reason)
                .register(meterRegistry)
                .increment();
    }

    public void recordHCADBaselineConfidence(double confidenceScore, String userSegment) {
        baselineConfidenceDistribution.record(confidenceScore);

        Gauge.builder("evolution.hcad.baseline.confidence.by_segment", () -> confidenceScore)
                .tag("user_segment", userSegment)
                .register(meterRegistry);
    }

    public void updateHCADLearningRate(double learningRate, String confidenceTier) {
        Gauge.builder("evolution.hcad.learning.rate.by_tier", () -> learningRate)
                .tag("confidence_tier", confidenceTier)
                .register(meterRegistry);
    }

    private String getConfidenceBucket(double confidenceScore) {
        if (confidenceScore >= 0.9) return "0.9-1.0";
        else if (confidenceScore >= 0.8) return "0.8-0.9";
        else if (confidenceScore >= 0.7) return "0.7-0.8";
        else if (confidenceScore >= 0.5) return "0.5-0.7";
        else return "0.0-0.5";
    }

    private double calculateAutoApprovalRate() {
        long total = totalProposals.get();
        long approved = approvedProposals.get();
        return total > 0 ? (double) approved / total : 0.0;
    }

    private double calculateHighConfidenceRatio() {
        long total = totalProposals.get();
        long highConf = highConfidenceProposals.get();
        return total > 0 ? (double) highConf / total : 0.0;
    }

    private double calculateAISuccessRate() {
        double success = aiCallSuccessCounter.count();
        double failure = aiCallFailureCounter.count();
        double total = success + failure;
        return total > 0 ? success / total : 1.0;
    }

    private void updateEvolutionHealth() {
        double autoApprovalRate = calculateAutoApprovalRate();
        double highConfidenceRatio = calculateHighConfidenceRatio();
        double aiSuccessRate = calculateAISuccessRate();

        double healthScore = (autoApprovalRate * 0.3) + (highConfidenceRatio * 0.3) + (aiSuccessRate * 0.4);
        unifiedMetrics.updateDomainHealth("evolution", healthScore);
    }

    public double getHealthScore() {
        return unifiedMetrics.getDomainHealth("evolution");
    }

    public void recordHCADAnalysis(long processingTimeMs, double anomalyScore, boolean wasBlocked) {
        
        Timer.builder("hcad.analysis.duration")
                .tag("blocked", String.valueOf(wasBlocked))
                .register(meterRegistry)
                .record(processingTimeMs, java.util.concurrent.TimeUnit.MILLISECONDS);

        DistributionSummary.builder("hcad.analysis.anomaly_score")
                .tag("blocked", String.valueOf(wasBlocked))
                .register(meterRegistry)
                .record(anomalyScore);

        if (wasBlocked) {
            Counter.builder("hcad.analysis.blocked")
                    .register(meterRegistry)
                    .increment();
        }

        if (anomalyScore >= 0.7 && !wasBlocked) {
            Counter.builder("hcad.analysis.warned")
                    .register(meterRegistry)
                    .increment();
        }

        if (processingTimeMs > 30) {
            Counter.builder("hcad.analysis.slow_requests")
                    .register(meterRegistry)
                    .increment();
        }

        Counter.builder("hcad.analysis.total")
                .tag("blocked", String.valueOf(wasBlocked))
                .register(meterRegistry)
                .increment();
    }

    public void recordHCADLearningDecision(String userId, String phase, String decision, double confidence) {
        Counter.builder("hcad.learning.decisions")
                .tag("phase", phase)
                .tag("decision", decision)
                .register(meterRegistry)
                .increment();

        baselineConfidenceDistribution.record(confidence);
    }

    @Override
    public String getDomain() {
        return "evolution";
    }

    @Override
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("proposals_created", proposalCreatedCounter.count());
        stats.put("proposals_approved", proposalApprovedCounter.count());
        stats.put("proposals_rejected", proposalRejectedCounter.count());
        stats.put("approval_rate", totalProposals.get() > 0 ?
            (double) approvedProposals.get() / totalProposals.get() : 0.0);
        stats.put("high_confidence_rate", totalProposals.get() > 0 ?
            (double) highConfidenceProposals.get() / totalProposals.get() : 0.0);
        stats.put("ai_success_rate",
            (aiCallSuccessCounter.count() + aiCallFailureCounter.count()) > 0 ?
            aiCallSuccessCounter.count() / (aiCallSuccessCounter.count() + aiCallFailureCounter.count()) : 0.0);
        stats.put("baseline_updates", baselineUpdatesCounter.count());
        stats.put("vector_documents_stored", vectorStoreDocumentsStoredCounter.count());
        return stats;
    }

    @Override
    public void reset() {
        totalProposals.set(0);
        approvedProposals.set(0);
        highConfidenceProposals.set(0);
    }

    @Override
    public Map<String, Double> getKeyMetrics() {
        Map<String, Double> metrics = new HashMap<>();
        metrics.put("proposal_count", (double) proposalCreatedCounter.count());
        metrics.put("approval_rate", totalProposals.get() > 0 ?
            (double) approvedProposals.get() / totalProposals.get() : 0.0);
        metrics.put("ai_success_rate",
            (aiCallSuccessCounter.count() + aiCallFailureCounter.count()) > 0 ?
            aiCallSuccessCounter.count() / (aiCallSuccessCounter.count() + aiCallFailureCounter.count()) : 0.0);
        metrics.put("baseline_update_count", (double) baselineUpdatesCounter.count());
        metrics.put("health_score", getHealthScore());
        return metrics;
    }

    @Override
    public void recordEvent(String eventType, Map<String, Object> metadata) {
        switch (eventType) {
            case "proposal_created":
                String proposalType = metadata.containsKey("proposalType") ?
                    (String) metadata.get("proposalType") : "unknown";
                String riskLevel = metadata.containsKey("riskLevel") ?
                    (String) metadata.get("riskLevel") : "low";
                double confidence = metadata.containsKey("confidence") ?
                    ((Number) metadata.get("confidence")).doubleValue() : 0.0;
                long duration = metadata.containsKey("duration") ?
                    ((Number) metadata.get("duration")).longValue() : 0L;
                recordProposalCreation(duration, proposalType, riskLevel, confidence);
                break;
            case "proposal_approved":
                String approvalMethod = metadata.containsKey("method") ?
                    (String) metadata.get("method") : "manual";
                recordProposalApproval(approvalMethod);
                break;
            case "proposal_rejected":
                String reason = metadata.containsKey("reason") ?
                    (String) metadata.get("reason") : "unknown";
                recordProposalRejection(reason);
                break;
            case "baseline_update":
                String phase = metadata.containsKey("phase") ?
                    (String) metadata.get("phase") : "unknown";
                String decision = metadata.containsKey("decision") ?
                    (String) metadata.get("decision") : "updated";
                recordHCADBaselineUpdate(phase, decision);
                break;
            case "ai_call_success":
                long aiDuration = metadata.containsKey("duration") ?
                    ((Number) metadata.get("duration")).longValue() : 0L;
                String model = metadata.containsKey("model") ?
                    (String) metadata.get("model") : "unknown";
                recordAICall(aiDuration, model, true);
                break;
            case "ai_call_failure":
                String failedModel = metadata.containsKey("model") ?
                    (String) metadata.get("model") : "unknown";
                recordAICall(0, failedModel, false);
                break;
            default:
                log.warn("Unknown event type: {}", eventType);
        }
    }

    @Override
    public void recordDuration(String operationName, long durationNanos) {
        if ("ai_call".equals(operationName)) {
            recordAICall(durationNanos / 1_000_000, "unknown", true); 
        }
    }
}
