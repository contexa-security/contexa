package io.contexa.contexacore.autonomous.domain;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.ProposalImpactLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ImpactAnalysisDTO {
    
    private Long proposalId;
    private ProposalImpactLevel impactLevel;
    private ProposalImpactLevel adjustedImpactLevel;
    private Double expectedImpact;
    private Double actualImpact;
    private Double confidenceScore;
    private Map<String, Object> impactFactors;
    private String recommendation;
    private boolean autoApprovalEligible;
    private int requiredApprovers;
    private LocalDateTime analysisTime;
}