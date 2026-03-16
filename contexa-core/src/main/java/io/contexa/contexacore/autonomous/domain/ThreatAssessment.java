package io.contexa.contexacore.autonomous.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ThreatAssessment {

    private String eventId;
    private double riskScore;
    private LocalDateTime assessedAt;
    private String strategyName;
    private double confidence;
    private String action;
    private String reasoning;

    @Builder.Default
    private boolean shouldEscalate = false;

    public double getConfidenceScore() {
        return confidence;
    }

}
