package io.contexa.contexacoreenterprise.domain.dto;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalStatus;
import io.contexa.contexacoreenterprise.autonomous.governance.PolicyApprovalService;
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
public class ProposalDetailDTO {
    
    private Long proposalId;
    private String title;
    private String description;
    private PolicyEvolutionProposal.ProposalType proposalType;
    private ProposalStatus status;
    private PolicyEvolutionProposal.RiskLevel riskLevel;

    private String sourceEventId;
    private String analysisLabId;
    private String aiReasoning;
    private Map<String, Object> evidenceContext;

    private String spelExpression;
    private String policyContent;

    private Double confidenceScore;
    private Double expectedImpact;
    private Double actualImpact;

    private Map<String, Object> metadata;

    private LocalDateTime createdAt;
    private LocalDateTime reviewedAt;
    private LocalDateTime activatedAt;

    private String reviewedBy;
    private String approvedBy;
    private String rejectionReason;

    private PolicyApprovalService.ApprovalHistory approvalHistory;
}