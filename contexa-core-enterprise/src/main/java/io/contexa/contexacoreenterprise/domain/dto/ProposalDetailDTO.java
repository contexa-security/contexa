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

/**
 * 제안 상세 DTO
 * 
 * @author contexa
 * @since 1.0.0
 */
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
    
    // 근거 정보
    private String sourceEventId;
    private String analysisLabId;
    private String aiReasoning;
    private Map<String, Object> evidenceContext;
    
    // 실행 정보
    private String spelExpression;
    private String policyContent;
    
    // 효과 측정
    private Double confidenceScore;
    private Double expectedImpact;
    private Double actualImpact;
    
    // 메타데이터
    private Map<String, Object> metadata;
    
    // 시간 정보
    private LocalDateTime createdAt;
    private LocalDateTime reviewedAt;
    private LocalDateTime activatedAt;
    
    // 승인 정보
    private String reviewedBy;
    private String approvedBy;
    private String rejectionReason;
    
    // 승인 이력
    private PolicyApprovalService.ApprovalHistory approvalHistory;
}