package io.contexa.contexacore.autonomous.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

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
    private String reasoning;
    private Boolean autonomyConstraintApplied;
    private List<String> autonomyConstraintReasons;
    private String autonomyConstraintSummary;

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


