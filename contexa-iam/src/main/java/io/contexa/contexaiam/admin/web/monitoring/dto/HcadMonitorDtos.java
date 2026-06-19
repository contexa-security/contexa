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

import java.util.List;

public final class HcadMonitorDtos {

    private HcadMonitorDtos() {
    }

    public record HcadSummary(
            String period,
            String from,
            String to,
            String currentMode,
            long candidateCount,
            long triggeredLlmCount,
            long truePositiveCount,
            long falsePositiveCount,
            long observableFalseNegativeCount,
            long trueNegativeCount,
            long unknownCount,
            long duplicateSuppressedCount,
            double precision,
            double unknownRate,
            double averageLlmLatencyMs,
            long estimatedWastedLlmCalls,
            double estimatedWasteCostUsd,
            Qualification qualification,
            String recommendation,
            List<Breakdown> modeBreakdown,
            List<Breakdown> signalBreakdown,
            List<ResourceBreakdown> resourceBreakdown,
            List<UserSessionBreakdown> userSessionBreakdown,
            List<RecentEvaluation> recentEvaluations,
            List<RecentEvaluation> unknownEvaluations
    ) {
    }

    public record Qualification(
            double shadowMinPrecision,
            double limitedEnforceMinPrecision,
            double defaultEnforceMinPrecision,
            int minimumSampleSize,
            double estimatedLlmCallCostUsd
    ) {
    }

    public record Breakdown(
            String key,
            long candidateCount,
            long truePositiveCount,
            long falsePositiveCount,
            long unknownCount,
            double precision
    ) {
    }

    public record ResourceBreakdown(
            String path,
            String method,
            long candidateCount,
            long truePositiveCount,
            long falsePositiveCount,
            long duplicateSuppressedCount,
            double precision
    ) {
    }

    public record UserSessionBreakdown(
            String userId,
            String contextBindingHash,
            long candidateCount,
            long triggeredLlmCount,
            long duplicateSuppressedCount,
            long truePositiveCount,
            long falsePositiveCount,
            long unknownCount,
            double precision
    ) {
    }

    public record RecentEvaluation(
            String evaluationId,
            String requestId,
            String userId,
            String method,
            String path,
            String mode,
            Integer earlyAnalysisScore,
            String band,
            Boolean triggeredLlm,
            Boolean duplicateSuppressed,
            String llmAction,
            Double llmRiskScore,
            Double llmConfidence,
            String outcomeClass,
            String createdAt,
            String decidedAt
    ) {
    }
}
