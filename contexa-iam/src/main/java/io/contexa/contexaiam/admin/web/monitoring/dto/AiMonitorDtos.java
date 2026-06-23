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
package io.contexa.contexaiam.admin.web.monitoring.dto;

import io.contexa.contexaiam.admin.web.monitoring.dto.HcadMonitorDtos.HcadSummary;

import java.util.List;

public final class AiMonitorDtos {

    private AiMonitorDtos() {
    }

    public record MonitorSnapshot(
            String period,
            String from,
            String to,
            String generatedAt
    ) {
    }

    public record MetricValue(
            String key,
            String label,
            String description,
            Double value,
            Long numerator,
            Long denominator,
            String unit,
            String noDataReason
    ) {
    }

    public record StandardMetrics(
            MetricValue observedRequests,
            MetricValue hcadEvaluations,
            MetricValue hcadAiConnected,
            MetricValue totalAiDecisions,
            MetricValue clearOutcomes,
            MetricValue hcadPrecision,
            MetricValue matchRate,
            MetricValue mismatchRate,
            MetricValue falsePositiveRate,
            MetricValue observableFalseNegativeRate,
            MetricValue unknownRate,
            MetricValue failureRate,
            MetricValue timeoutRate,
            MetricValue averageLatencyMs
    ) {
    }

    public record OverviewSummary(
            String period,
            String from,
            String to,
            String generatedAt,
            MonitorSnapshot snapshot,
            StandardMetrics metrics,
            HcadSummary hcad,
            LlmDecisionSummary llm,
            CorrelationSummary correlation,
            OperationsSummary operations,
            String readinessRecommendation
    ) {
    }

    public record LlmDecisionSummary(
            MonitorSnapshot snapshot,
            StandardMetrics metrics,
            long totalDecisionCount,
            long hcadPreTriggerDecisionCount,
            long protectableDecisionCount,
            long hcadAndProtectableDecisionCount,
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
            List<NamedCount> confidenceDistribution
    ) {
    }

    public record CorrelationSummary(
            MonitorSnapshot snapshot,
            StandardMetrics metrics,
            long truePositiveCount,
            long falsePositiveCount,
            long observableFalseNegativeCount,
            long trueNegativeCount,
            long unknownCount,
            long unobservedCount,
            List<NamedCount> triggerRelationBreakdown,
            List<NamedCount> outcomeBreakdown,
            List<CorrelationMatrixRow> matrixRows,
            List<NamedCount> notCalledReasonBreakdown,
            List<RecentCorrelation> recentCorrelations
    ) {
    }

    public record OperationsSummary(
            double averageLatencyMs,
            long parserFailureCount,
            long technicalFallbackCount,
            long timeoutCount,
            long modelUnavailableCount,
            long estimatedWastedLlmCalls,
            double estimatedWasteCostUsd,
            double estimatedSavedCostUsd
    ) {
    }

    public record NamedCount(
            String key,
            long count
    ) {
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
            List<RecentFailure> slowRequests
    ) {
    }

    public record ReadinessSummary(
            String period,
            String from,
            String to,
            String generatedAt,
            MonitorSnapshot snapshot,
            StandardMetrics metrics,
            String recommendation,
            long minimumSampleSize,
            long hcadCandidateCount,
            long llmDecisionCount,
            double hcadPrecision,
            double observableFalseNegativeRate,
            double unknownRate,
            double failureRate,
            double parserFailureRate,
            double technicalFallbackRate,
            double timeoutRate,
            double modelUnavailableRate,
            double averageLatencyMs,
            double p95LatencyMs,
            double estimatedWasteCostUsd,
            double estimatedSavedCostUsd
    ) {
    }

    public record CorrelationMatrixRow(
            String key,
            long llmRiskCount,
            long llmAllowCount,
            long llmUnknownCount,
            long llmNotCalledCount
    ) {
    }

    public record RecentCorrelation(
            String correlationId,
            String hcadEvaluationId,
            String llmObservationId,
            String eventId,
            String requestId,
            String userId,
            String triggerRelation,
            String outcomeClass,
            Integer hcadScore,
            String hcadBand,
            Boolean hcadEligible,
            String llmFinalAction,
            String llmProposedAction,
            Double llmRiskScore,
            Double llmConfidence,
            String createdAt,
            String decidedAt
    ) {
    }

    public record AffectedRequest(
            String method,
            String path,
            long count
    ) {
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
            String createdAt
    ) {
    }
}
