package io.contexa.contexacore.autonomous.controller;

import io.contexa.contexacore.autonomous.domain.*;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.autonomous.evolution.PolicyActivationService;
import io.contexa.contexacore.autonomous.governance.ApprovalService;
import io.contexa.contexacore.autonomous.governance.PolicyEvolutionGovernance;
import io.contexa.contexacore.autonomous.governance.SynthesisPolicyRepository;
import io.contexa.contexacore.autonomous.monitor.PolicyProposalAnalytics;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 정책 워크벤치 컨트롤러
 * 
 * 정책 제안 관리를 위한 REST API를 제공합니다.
 * 관리자가 제안을 검토, 승인, 거부할 수 있는 엔드포인트를 제공합니다.
 * 
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@RestController
@RequestMapping("/api/policies")
@RequiredArgsConstructor
@CrossOrigin(origins = "*", maxAge = 3600)
public class PolicyWorkbenchController {
    
    private final PolicyProposalRepository proposalRepository;
    private final PolicyActivationService activationService;
    private final ApprovalService approvalService;
    private final PolicyEvolutionGovernance governanceService;
    private final SynthesisPolicyRepository synthesisPolicyRepository;
    private final PolicyProposalAnalytics analyticsService;
    
    /**
     * 제안 목록 조회
     * 
     * @param status 상태 필터 (선택)
     * @param pageable 페이징 정보
     * @return 제안 목록
     */
    @GetMapping("/proposals")
    public ResponseEntity<Page<ProposalListDTO>> getProposals(
            @RequestParam(required = false) String status,
            Pageable pageable) {
        
        log.info("Fetching proposals with status: {}", status);
        
        try {
            Page<PolicyEvolutionProposal> proposals;
            
            if (status != null && !status.isEmpty()) {
                proposals = proposalRepository.findByStatus(
                    PolicyEvolutionProposal.ProposalStatus.valueOf(status.toUpperCase()), 
                    pageable
                );
            } else {
                proposals = proposalRepository.findAll(pageable);
            }
            
            Page<ProposalListDTO> dtoPage = proposals.map(this::toListDTO);
            
            return ResponseEntity.ok(dtoPage);
            
        } catch (Exception e) {
            log.error("Error fetching proposals", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    
    /**
     * 제안 상세 조회
     * 
     * @param id 제안 ID
     * @return 제안 상세 정보
     */
    @GetMapping("/proposals/{id}")
    public ResponseEntity<ProposalDetailDTO> getProposalDetail(@PathVariable Long id) {
        log.info("Fetching proposal detail for ID: {}", id);
        
        try {
            PolicyEvolutionProposal proposal = proposalRepository.findById(id)
                .orElse(null);
            
            if (proposal == null) {
                return ResponseEntity.notFound().build();
            }
            
            ProposalDetailDTO dto = toDetailDTO(proposal);
            
            // 승인 이력 추가
            ApprovalService.ApprovalHistory history = approvalService.getApprovalHistory(id);
            dto.setApprovalHistory(history);
            
            return ResponseEntity.ok(dto);
            
        } catch (Exception e) {
            log.error("Error fetching proposal detail", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    
    /**
     * 제안 승인
     * 
     * @param id 제안 ID
     * @param request 승인 요청
     * @return 승인 결과
     */
    @PostMapping("/proposals/{id}/approve")
    public ResponseEntity<ApprovalResponseDTO> approveProposal(
            @PathVariable Long id,
            @Valid @RequestBody ApprovalRequestDTO request) {
        
        log.info("Approving proposal {} by {}", id, request.getApproverId());
        
        try {
            // 1. 승인 처리
            if (request.getRequestId() != null) {
                // 특정 승인 요청 처리
                ApprovalService.ApprovalResult result = approvalService.processApproval(
                    request.getRequestId(),
                    request.getApproverId(),
                    ApprovalService.ApprovalDecision.APPROVE,
                    request.getComments()
                );
                
                ApprovalResponseDTO response = ApprovalResponseDTO.builder()
                    .proposalId(id)
                    .success(true)
                    .message("Approval processed successfully")
                    .workflowComplete(result.isWorkflowComplete())
                    .timestamp(LocalDateTime.now())
                    .build();
                
                return ResponseEntity.ok(response);
                
            } else {
                // 직접 승인 (거버넌스 우회)
                PolicyEvolutionProposal proposal = proposalRepository.findById(id)
                    .orElseThrow(() -> new IllegalArgumentException("Proposal not found"));
                
                proposal.approve(request.getApproverId());
                proposalRepository.save(proposal);
                
                // 정책 활성화
                PolicyActivationService.ActivationResult activationResult = 
                    activationService.activatePolicy(id, request.getApproverId());
                
                ApprovalResponseDTO response = ApprovalResponseDTO.builder()
                    .proposalId(id)
                    .success(activationResult.isSuccess())
                    .message(activationResult.getMessage())
                    .activated(activationResult.isSuccess())
                    .timestamp(LocalDateTime.now())
                    .build();
                
                return ResponseEntity.ok(response);
            }
            
        } catch (Exception e) {
            log.error("Error approving proposal", e);
            
            ApprovalResponseDTO response = ApprovalResponseDTO.builder()
                .proposalId(id)
                .success(false)
                .message("Approval failed: " + e.getMessage())
                .timestamp(LocalDateTime.now())
                .build();
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
    
    /**
     * 제안 거부
     * 
     * @param id 제안 ID
     * @param request 거부 요청
     * @return 거부 결과
     */
    @PostMapping("/proposals/{id}/reject")
    public ResponseEntity<ApprovalResponseDTO> rejectProposal(
            @PathVariable Long id,
            @Valid @RequestBody ApprovalRequestDTO request) {
        
        log.info("Rejecting proposal {} by {}", id, request.getApproverId());
        
        try {
            if (request.getRequestId() != null) {
                // 특정 승인 요청 거부
                ApprovalService.ApprovalResult result = approvalService.processApproval(
                    request.getRequestId(),
                    request.getApproverId(),
                    ApprovalService.ApprovalDecision.REJECT,
                    request.getComments()
                );
                
                ApprovalResponseDTO response = ApprovalResponseDTO.builder()
                    .proposalId(id)
                    .success(true)
                    .message("Rejection processed successfully")
                    .workflowComplete(result.isWorkflowComplete())
                    .timestamp(LocalDateTime.now())
                    .build();
                
                return ResponseEntity.ok(response);
                
            } else {
                // 직접 거부
                PolicyEvolutionProposal proposal = proposalRepository.findById(id)
                    .orElseThrow(() -> new IllegalArgumentException("Proposal not found"));
                
                proposal.reject("user", request.getComments());
                proposalRepository.save(proposal);
                
                ApprovalResponseDTO response = ApprovalResponseDTO.builder()
                    .proposalId(id)
                    .success(true)
                    .message("Proposal rejected")
                    .timestamp(LocalDateTime.now())
                    .build();
                
                return ResponseEntity.ok(response);
            }
            
        } catch (Exception e) {
            log.error("Error rejecting proposal", e);
            
            ApprovalResponseDTO response = ApprovalResponseDTO.builder()
                .proposalId(id)
                .success(false)
                .message("Rejection failed: " + e.getMessage())
                .timestamp(LocalDateTime.now())
                .build();
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
    
    /**
     * 영향도 분석
     * 
     * @param id 제안 ID
     * @return 영향도 분석 결과
     */
    @GetMapping("/proposals/{id}/impact")
    public ResponseEntity<ImpactAnalysisDTO> analyzeImpact(@PathVariable Long id) {
        log.info("Analyzing impact for proposal: {}", id);
        
        try {
            PolicyEvolutionProposal proposal = proposalRepository.findById(id)
                .orElse(null);
            
            if (proposal == null) {
                return ResponseEntity.notFound().build();
            }
            
            // 위험도 재평가
            PolicyEvolutionGovernance.GovernanceDecision decision = 
                governanceService.evaluateProposal(id);
            
            ImpactAnalysisDTO analysis = ImpactAnalysisDTO.builder()
                .proposalId(id)
                .riskLevel(proposal.getRiskLevel())
                .adjustedRiskLevel(decision.getRiskAssessment() != null ? 
                    decision.getRiskAssessment().getAdjustedRisk() : proposal.getRiskLevel())
                .expectedImpact(proposal.getExpectedImpact())
                .actualImpact(proposal.getActualImpact())
                .confidenceScore(proposal.getConfidenceScore())
                .riskFactors(decision.getRiskAssessment() != null ? 
                    decision.getRiskAssessment().getRiskFactors() : null)
                .recommendation(decision.getReason())
                .autoApprovalEligible(decision.isAutoApproved())
                .requiredApprovers(decision.getRequiredApprovers())
                .analysisTime(LocalDateTime.now())
                .build();
            
            return ResponseEntity.ok(analysis);
            
        } catch (Exception e) {
            log.error("Error analyzing impact", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    
    /**
     * 분석 통계 조회
     * 
     * @param period 기간 (DAILY, WEEKLY, MONTHLY)
     * @return 통계 정보
     */
    @GetMapping("/analytics")
    public ResponseEntity<AnalyticsDTO> getAnalytics(
            @RequestParam(defaultValue = "WEEKLY") String period) {
        
        log.info("Fetching analytics for period: {}", period);
        
        try {
            // 기간별 분석
            int days = 7; // 기본값
            if ("DAILY".equalsIgnoreCase(period)) {
                days = 1;
            } else if ("WEEKLY".equalsIgnoreCase(period)) {
                days = 7;
            } else if ("MONTHLY".equalsIgnoreCase(period)) {
                days = 30;
            }
            
            // 분석 데이터 생성
            PolicyProposalAnalytics.DashboardStatistics stats = analyticsService.generateDashboardStatistics();
            PolicyProposalAnalytics.TrendAnalysis trends = analyticsService.analyzeTrends(days);
            
            // 타입 변환
            Map<String, Integer> proposalsByTypeConverted = new HashMap<>();
            if (stats.getProposalsByType() != null) {
                stats.getProposalsByType().forEach((type, count) -> 
                    proposalsByTypeConverted.put(type.toString(), count.intValue()));
            }
            
            Map<String, Integer> proposalsByRiskConverted = new HashMap<>();
            if (stats.getProposalsByRiskLevel() != null) {
                stats.getProposalsByRiskLevel().forEach((risk, count) -> 
                    proposalsByRiskConverted.put(risk.toString(), count.intValue()));
            }
            
            AnalyticsDTO analytics = AnalyticsDTO.builder()
                .totalProposals((int) stats.getTotalProposals())
                .approvalRate(stats.getApprovalRate())
                .proposalsByType(proposalsByTypeConverted)
                .proposalsByRiskLevel(proposalsByRiskConverted)
                .build();
            
            return ResponseEntity.ok(analytics);
            
        } catch (Exception e) {
            log.error("Error fetching analytics", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    
    /**
     * 활성 정책 조회
     * 
     * @return 활성 정책 목록
     */
    @GetMapping("/active")
    public ResponseEntity<List<PolicyDTO>> getActivePolicies() {
        log.info("Fetching active policies");
        
        try {
            List<SynthesisPolicyRepository.Policy> policies = synthesisPolicyRepository.findActivePolices();
            
            List<PolicyDTO> dtos = policies.stream()
                .map(this::toPolicyDTO)
                .collect(Collectors.toList());
            
            return ResponseEntity.ok(dtos);
            
        } catch (Exception e) {
            log.error("Error fetching active policies", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    
    /**
     * 정책 비활성화
     * 
     * @param policyId 정책 ID
     * @param request 비활성화 요청
     * @return 비활성화 결과
     */
    @PostMapping("/policies/{policyId}/deactivate")
    public ResponseEntity<PolicyOperationResultDTO> deactivatePolicy(
            @PathVariable Long policyId,
            @RequestBody DeactivationRequestDTO request) {
        
        log.info("Deactivating policy {} by {}", policyId, request.getDeactivatedBy());
        
        try {
            // 정책 찾기
            SynthesisPolicyRepository.Policy policy = synthesisPolicyRepository.findById(policyId)
                .orElseThrow(() -> new IllegalArgumentException("Policy not found"));
            
            // 비활성화
            synthesisPolicyRepository.deactivate(policyId, request.getReason());
            
            // 제안도 비활성화
            if (policy.getProposalId() != null) {
                activationService.deactivatePolicy(
                    policy.getProposalId(), 
                    request.getDeactivatedBy(), 
                    request.getReason()
                );
            }
            
            PolicyOperationResultDTO result = PolicyOperationResultDTO.builder()
                .policyId(policyId)
                .operation("DEACTIVATE")
                .success(true)
                .message("Policy deactivated successfully")
                .timestamp(LocalDateTime.now())
                .build();
            
            return ResponseEntity.ok(result);
            
        } catch (Exception e) {
            log.error("Error deactivating policy", e);
            
            PolicyOperationResultDTO result = PolicyOperationResultDTO.builder()
                .policyId(policyId)
                .operation("DEACTIVATE")
                .success(false)
                .message("Deactivation failed: " + e.getMessage())
                .timestamp(LocalDateTime.now())
                .build();
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(result);
        }
    }
    
    /**
     * 대기 중인 승인 요청 조회
     * 
     * @param approverId 승인자 ID
     * @return 승인 요청 목록
     */
    @GetMapping("/approvals/pending")
    public ResponseEntity<List<PendingApprovalDTO>> getPendingApprovals(
            @RequestParam String approverId) {
        
        log.info("Fetching pending approvals for: {}", approverId);
        
        try {
            // 대기 중인 제안 조회
            List<PolicyEvolutionProposal> pendingProposals = 
                proposalRepository.findByStatus(PolicyEvolutionProposal.ProposalStatus.PENDING);
            
            List<PendingApprovalDTO> pendingApprovals = pendingProposals.stream()
                .map(proposal -> {
                    ApprovalService.ApprovalHistory history = 
                        approvalService.getApprovalHistory(proposal.getId());
                    
                    // 해당 승인자의 대기 중인 요청 찾기
                    return history.getRequests().stream()
                        .filter(req -> req.getApprover().getApproverId().equals(approverId))
                        .filter(req -> req.getStatus() == ApprovalService.RequestStatus.PENDING)
                        .map(req -> PendingApprovalDTO.builder()
                            .requestId(req.getRequestId())
                            .proposalId(proposal.getId())
                            .proposalTitle(proposal.getTitle())
                            .proposalType(proposal.getProposalType())
                            .riskLevel(proposal.getRiskLevel())
                            .createdAt(req.getCreatedAt())
                            .expiresAt(req.getExpiresAt())
                            .build())
                        .findFirst()
                        .orElse(null);
                })
                .filter(dto -> dto != null)
                .collect(Collectors.toList());
            
            return ResponseEntity.ok(pendingApprovals);
            
        } catch (Exception e) {
            log.error("Error fetching pending approvals", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    
    // ==================== Private Methods ====================
    
    private ProposalListDTO toListDTO(PolicyEvolutionProposal proposal) {
        return ProposalListDTO.builder()
            .proposalId(proposal.getId())
            .title(proposal.getTitle())
            .proposalType(proposal.getProposalType())
            .status(proposal.getStatus())
            .riskLevel(proposal.getRiskLevel())
            .confidenceScore(proposal.getConfidenceScore())
            .createdAt(proposal.getCreatedAt())
            .reviewedAt(proposal.getReviewedAt())
            .build();
    }
    
    private ProposalDetailDTO toDetailDTO(PolicyEvolutionProposal proposal) {
        return ProposalDetailDTO.builder()
            .proposalId(proposal.getId())
            .title(proposal.getTitle())
            .description(proposal.getDescription())
            .proposalType(proposal.getProposalType())
            .status(proposal.getStatus())
            .riskLevel(proposal.getRiskLevel())
            .sourceEventId(proposal.getSourceEventId())
            .analysisLabId(proposal.getAnalysisLabId())
            .aiReasoning(proposal.getAiReasoning())
            .spelExpression(proposal.getSpelExpression())
            .policyContent(proposal.getPolicyContent())
            .evidenceContext(proposal.getEvidenceContext())
            .confidenceScore(proposal.getConfidenceScore())
            .expectedImpact(proposal.getExpectedImpact())
            .actualImpact(proposal.getActualImpact())
            .metadata(proposal.getMetadata())
            .createdAt(proposal.getCreatedAt())
            .reviewedAt(proposal.getReviewedAt())
            .activatedAt(proposal.getActivatedAt())
            .reviewedBy(proposal.getReviewedBy())
            .approvedBy(proposal.getApprovedBy())
            .rejectionReason(proposal.getRejectionReason())
            .build();
    }
    
    private PolicyDTO toPolicyDTO(SynthesisPolicyRepository.Policy policy) {
        return PolicyDTO.builder()
            .policyId(policy.getPolicyId())
            .proposalId(policy.getProposalId())
            .policyName(policy.getPolicyName())
            .policyType(policy.getPolicyType())
            .spelExpression(policy.getSpelExpression())
            .status(policy.getStatus())
            .version(policy.getVersion())
            .createdAt(policy.getCreatedAt())
            .activatedAt(policy.getActivatedAt())
            .build();
    }
}