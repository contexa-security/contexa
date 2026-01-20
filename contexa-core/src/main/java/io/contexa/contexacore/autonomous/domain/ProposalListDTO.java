package io.contexa.contexacore.autonomous.domain;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProposalListDTO {
    
    private Long proposalId;
    private String title;
    private PolicyEvolutionProposal.ProposalType proposalType;
    private ProposalStatus status;
    private PolicyEvolutionProposal.RiskLevel riskLevel;
    private Double confidenceScore;
    private LocalDateTime createdAt;
    private LocalDateTime reviewedAt;
}