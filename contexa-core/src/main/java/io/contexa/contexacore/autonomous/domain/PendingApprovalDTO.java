package io.contexa.contexacore.autonomous.domain;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 대기 중인 승인 DTO
 * 
 * @author AI3Security
 * @since 1.0.0
 */
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