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
    private Double confidence;
    private Double llmAuditConfidence;
    private String action;
    private String reasoning;

    @Builder.Default
    private boolean shouldEscalate = false;

    public Double getConfidenceScore() {
        return resolveAuditConfidence();
    }

    public Double resolveAuditRiskScore() {
        return llmAuditRiskScore;
    }

    public Double resolveAuditConfidence() {
        return llmAuditConfidence;
    }

}


