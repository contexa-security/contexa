package io.contexa.contexacore.autonomous.domain;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PendingApprovalDTO {
    
    private String requestId;
    private Long proposalId;
    private String proposalTitle;
    private PolicyEvolutionProposal.ProposalType proposalType;
    private PolicyEvolutionProposal.RiskLevel riskLevel;
    private LocalDateTime createdAt;
    private LocalDateTime expiresAt;
}