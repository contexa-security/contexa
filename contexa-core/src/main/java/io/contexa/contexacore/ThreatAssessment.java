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
package io.contexa.contexacore;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ThreatAssessment {

    private String eventId;
    private Double riskScore;
    private Double llmAuditRiskScore;
    private LocalDateTime assessedAt;
    private List<String> indicators;
    private List<String> recommendedActions;
    private String strategyName;
    /**
     * Effective confidence after runtime autonomy constraints.
     */
    private Double confidence;
    /**
     * Raw confidence proposed by the LLM.
     */
    private Double llmAuditConfidence;
    /**
     * LLM semantic action proposal.
     */
    private String action;
    /**
     * Final action used for autonomous execution. Null means the proposal stands as-is.
     */
    private String autonomousAction;
    private Boolean llmDecisionPresent;
    private Boolean technicalFallbackApplied;
    private String technicalFallbackCategory;
    private String technicalFallbackReason;
    private String technicalFallbackAction;
    private Boolean responseActionFallbackApplied;
    private String responseActionFallbackCategory;
    private String responseActionFallbackReason;
    private String responseActionFallbackAction;
    private String reasoning;
    private Boolean autonomyConstraintApplied;
    private List<String> autonomyConstraintReasons;
    private String autonomyConstraintSummary;
    private String autonomyConstraintPolicy;
    private String autonomyConstraintSource;
    private String autonomyConstraintVersion;
    private Map<String, String> fieldProvenance;

    @Builder.Default
    private boolean shouldEscalate = false;

    public Double getConfidenceScore() {
        return confidence != null ? confidence : resolveAuditConfidence();
    }

    public Double resolveAuditRiskScore() {
        return llmAuditRiskScore;
    }

    public Double resolveAuditConfidence() {
        return llmAuditConfidence;
    }
}
