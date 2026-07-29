/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.contexaiam.admin.web.monitoring.dto;

import java.util.List;

public final class AiMonitorDtos {

    private AiMonitorDtos() {
    }

    public record MonitorSnapshot(
            String period,
            String from,
            String to,
            String generatedAt,
            RuntimeModeSummary runtimeModes) {
    }

    public record RuntimeModeSummary(
            String llmMode,
            String llmEffectKey) {
    }

    public record MetricValue(
            String key,
            String label,
            String description,
            Double value,
            Long numerator,
            Long denominator,
            String unit,
            String noDataReason) {
    }

    public record StandardMetrics(
            MetricValue totalAiDecisions,
            MetricValue failureRate,
            MetricValue timeoutRate,
            MetricValue averageLatencyMs) {
    }

    public record OverviewSummary(
            String period,
            String from,
            String to,
            String generatedAt,
            MonitorSnapshot snapshot,
            StandardMetrics metrics,
            LlmDecisionSummary llm,
            OperationsSummary operations,
            String readinessRecommendation) {
    }

    public record LlmDecisionSummary(
            MonitorSnapshot snapshot,
            StandardMetrics metrics,
            long totalDecisionCount,
            long protectableDecisionCount,
            List<NamedCount> triggerSourceBreakdown,
            List<NamedCount> actionBreakdown,
            List<NamedCount> proposedActionBreakdown,
            List<NamedCount> finalActionBreakdown,
            List<NamedCount> providerBreakdown,
            List<NamedCount> modelBreakdown,
            List<NamedCount> promptTemplateBreakdown,
            long parserFailureCount,
            long technicalFallbackCount,
            long timeoutCount,
            long modelUnavailableCount,
            double parserFailureRate,
            double technicalFallbackRate,
            double timeoutRate,
            double modelUnavailableRate,
            double averageLatencyMs,
            double p95LatencyMs,
            List<NamedCount> riskScoreDistribution,
            List<NamedCount> confidenceDistribution) {
    }

    public record LatencyBreakdownMetric(
            String key,
            double averageMs,
            double p95Ms,
            double p99Ms) {
    }

    public record OperationsSummary(
            double averageLatencyMs,
            long parserFailureCount,
            long technicalFallbackCount,
            long timeoutCount,
            long modelUnavailableCount,
            long providerThrottleWaitCount,
            List<LatencyBreakdownMetric> latencyBreakdown) {
    }

    public record NamedCount(
            String key,
            long count) {
    }

    public record FailureSummary(
            String period,
            String from,
            String to,
            String generatedAt,
            MonitorSnapshot snapshot,
            StandardMetrics metrics,
            OperationsSummary operations,
            List<NamedCount> explicitFailureBreakdown,
            List<NamedCount> failureTypeBreakdown,
            List<NamedCount> fallbackCategoryBreakdown,
            List<NamedCount> providerBreakdown,
            List<NamedCount> modelBreakdown,
            List<NamedCount> promptTemplateBreakdown,
            List<NamedCount> failureTrend,
            List<AffectedRequest> affectedRequests,
            List<RecentFailure> recentFailures,
            List<RecentFailure> slowRequests) {
    }

    public record ReadinessSummary(
            String period,
            String from,
            String to,
            String generatedAt,
            MonitorSnapshot snapshot,
            StandardMetrics metrics,
            String recommendation,
            long llmDecisionCount,
            double failureRate,
            double parserFailureRate,
            double technicalFallbackRate,
            double timeoutRate,
            double modelUnavailableRate,
            double averageLatencyMs,
            double p95LatencyMs,
            MonitoringSessionCurrent currentSession,
            List<MonitoringSessionSummary> previousSessions,
            List<ReadinessBlocker> blockers) {
    }

    public record MonitoringSessionCurrent(
            String sessionId,
            String startedAt,
            String from,
            String to,
            long llmDecisionCount,
            String recommendation) {
    }

    public record MonitoringSessionSummary(
            String sessionId,
            String startedAt,
            String endedAt,
            String period,
            String resetBy,
            String resetReason,
            String llmMode,
            String llmProvider,
            String llmModel,
            String promptTemplateVersion,
            String policyVersion,
            long llmDecisionCount,
            double failureRate,
            double timeoutRate,
            double parserFailureRate,
            double modelUnavailableRate,
            double averageLatencyMs,
            double p95LatencyMs,
            String topBlockersJson,
            String recommendation) {
    }

    public record ReadinessBlocker(
            String key,
            String title,
            String current,
            String required,
            String action) {
    }

    public record MonitoringResetRequest(
            String reason,
            String confirmationText) {
    }

    public record MonitoringResetResponse(
            String sessionId,
            String startedAt,
            String endedAt,
            long deletedLlmObservationCount,
            MonitoringSessionSummary archivedSummary,
            MonitoringSessionCurrent newSession) {
    }

    public record AffectedRequest(
            String method,
            String path,
            long count) {
    }

    public record RecentFailure(
            String observationId,
            String requestId,
            String userId,
            String method,
            String path,
            String failureType,
            String finalAction,
            Double latencyMs,
            String createdAt) {
    }
}
