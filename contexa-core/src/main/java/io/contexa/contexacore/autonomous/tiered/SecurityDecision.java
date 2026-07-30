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
package io.contexa.contexacore.autonomous.tiered;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityDecision {

    /**
     * Primary semantic judgment proposed by the LLM.
     */
    private ZeroTrustAction action;
    private Double riskScore;
    /**
     * Effective confidence after autonomy constraints are applied.
     */
    private Double confidence;
    private Double llmAuditRiskScore;
    /**
     * Raw confidence emitted by the LLM before autonomy constraints.
     */
    private Double llmAuditConfidence;
    private long analysisTime;
    private long processingTimeMs;
    private int processingLayer;

    private String llmModel;

    private Map<String, Object> sessionContext;
    private List<String> behaviorPatterns;
    private String threatCategory;
    private List<String> mitigationActions;
    private String reasoning;
    /**
     * Raw reasoning emitted by the LLM before platform canonicalization or
     * autonomy constraints replace the operator-facing explanation.
     */
    private String llmReasoning;

    private List<String> iocIndicators;
    private Map<String, String> mitreMapping;
    private String soarPlaybook;
    private boolean requiresApproval;
    private String expertRecommendation;
    private String eventId;
    /**
     * Final action used for autonomous execution.
     * When null, the proposed action is also the enforced action.
     */
    private ZeroTrustAction autonomousAction;
    private Boolean llmDecisionPresent;
    private Boolean technicalFallbackApplied;
    private String technicalFallbackCategory;
    private String technicalFallbackReason;
    private String technicalFallbackAction;
    private Boolean responseActionFallbackApplied;
    private String responseActionFallbackCategory;
    private String responseActionFallbackReason;
    private String responseActionFallbackAction;
    private Boolean autonomyConstraintApplied;
    @Builder.Default
    private List<String> autonomyConstraintReasons = new ArrayList<>();
    private String autonomyConstraintSummary;
    private String autonomyConstraintPolicy;
    private String autonomyConstraintSource;
    private String autonomyConstraintVersion;
    private Map<String, String> fieldProvenance;

    public Double resolveAuditRiskScore() {
        return llmAuditRiskScore;
    }

    public Double resolveAuditConfidence() {
        return llmAuditConfidence;
    }

    public ZeroTrustAction resolveAutonomousAction() {
        return autonomousAction != null ? autonomousAction : action;
    }
}
