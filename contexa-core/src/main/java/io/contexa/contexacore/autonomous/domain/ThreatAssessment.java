package io.contexa.contexacore.autonomous.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ThreatAssessment {

    private String assessmentId;
    private String eventId;

    private double riskScore;
    
    
    
    private String description;
    private String evaluator;
    private LocalDateTime assessedAt;

    
    private List<String> indicators;
    
    
    
    
    private List<String> recommendedActions;
    
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