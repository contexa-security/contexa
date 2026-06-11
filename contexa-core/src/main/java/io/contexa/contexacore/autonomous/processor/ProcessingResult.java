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
package io.contexa.contexacore.autonomous.processor;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProcessingResult {

    private boolean success;

    private Double riskScore;

    private double currentRiskLevel;

    private Double llmAuditRiskScore;

    private ProcessingPath processingPath;

    /**
     * Final action applied by the runtime after autonomy constraints.
     */
    private String action;

    /**
     * Primary semantic action proposed by the LLM.
     */
    private String proposedAction;

    /**
     * Effective confidence after autonomy constraints.
     */
    private Double confidence;

    /**
     * Raw confidence proposed by the LLM.
     */
    private Double llmAuditConfidence;
    private Boolean llmDecisionPresent;
    private Boolean technicalFallbackApplied;
    private String technicalFallbackCategory;
    private String technicalFallbackReason;
    private String technicalFallbackAction;

    private String reasoning;

    @Builder.Default
    private Map<String, Object> analysisData = new HashMap<>();

    private List<String> threatIndicators;

    private long processingTimeMs;

    private LocalDateTime processedAt;

    private int aiAnalysisLevel;

    private List<String> recommendedActions;

    private ProcessingStatus status;

    private String errorMessage;

    private String message;

    private Boolean autonomyConstraintApplied;

    private List<String> autonomyConstraintReasons;

    private String autonomyConstraintSummary;

    public enum ProcessingPath {
        COLD_PATH("Cold Path - AI Analysis"),
        BYPASS("Bypass - No Processing");

        private final String description;

        ProcessingPath(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }

    public enum ProcessingStatus {
        SUCCESS("Processing completed successfully"),
        PARTIAL_SUCCESS("Processing partially completed"),
        FAILED("Processing failed"),
        TIMEOUT("Processing timeout"),
        SKIPPED("Processing skipped");

        private final String description;

        ProcessingStatus(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }

    public static ProcessingResult success(ProcessingPath path, Double riskScore) {
        return ProcessingResult.builder()
                .processingPath(path)
                .llmAuditRiskScore(riskScore)
                .riskScore(null)
                .success(true)
                .status(ProcessingStatus.SUCCESS)
                .processedAt(LocalDateTime.now())
                .build();
    }

    public static ProcessingResult failure(ProcessingPath path, String error) {
        return ProcessingResult.builder()
                .processingPath(path)
                .success(false)
                .status(ProcessingStatus.FAILED)
                .errorMessage(error)
                .processedAt(LocalDateTime.now())
                .build();
    }

    public void addAnalysisData(String key, Object value) {
        if (this.analysisData == null) {
            this.analysisData = new HashMap<>();
        }
        this.analysisData.put(key, value);
    }

    public void setProcessingComplete(long startTimeMs) {
        this.processingTimeMs = System.currentTimeMillis() - startTimeMs;
        this.processedAt = LocalDateTime.now();
    }

    public Double resolveAuditRiskScore() {
        return llmAuditRiskScore;
    }

    public Double resolveAuditConfidence() {
        return llmAuditConfidence;
    }
}
