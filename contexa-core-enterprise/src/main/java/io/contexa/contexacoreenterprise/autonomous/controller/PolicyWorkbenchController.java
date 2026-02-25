package io.contexa.contexacoreenterprise.autonomous.controller;

import io.contexa.contexacoreenterprise.domain.dto.PolicyDTO;
import io.contexa.contexacoreenterprise.domain.dto.ProposalDetailDTO;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.autonomous.PolicyActivationService;
import io.contexa.contexacoreenterprise.autonomous.governance.PolicyApprovalService;
import io.contexa.contexacoreenterprise.autonomous.governance.PolicyEvolutionGovernance;
import io.contexa.contexacoreenterprise.repository.SynthesisPolicyRepository;
import io.contexa.contexacore.autonomous.monitor.PolicyProposalAnalytics;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import io.contexa.contexacore.autonomous.domain.ProposalListDTO;
import io.contexa.contexacore.autonomous.domain.ApprovalRequestDTO;
import io.contexa.contexacore.autonomous.domain.ApprovalResponseDTO;
import io.contexa.contexacore.autonomous.domain.ImpactAnalysisDTO;
import io.contexa.contexacore.autonomous.domain.AnalyticsDTO;
import io.contexa.contexacore.autonomous.domain.PendingApprovalDTO;
import io.contexa.contexacore.autonomous.domain.DeactivationRequestDTO;
import io.contexa.contexacore.autonomous.domain.PolicyOperationResultDTO;
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

@Slf4j
@RestController
@RequestMapping("/api/policies")
@RequiredArgsConstructor
@CrossOrigin(origins = "${contexa.cors.allowed-origins:http://localhost:3000}", maxAge = 3600)
public class PolicyWorkbenchController {
    
    private final PolicyProposalRepository proposalRepository;
    private final PolicyActivationService activationService;
    private final PolicyApprovalService approvalService;
    private final PolicyEvolutionGovernance governanceService;
    private final SynthesisPolicyRepository synthesisPolicyRepository;
    private final PolicyProposalAnalytics analyticsService;

    @GetMapping("/proposals")
    public ResponseEntity<Page<ProposalListDTO>> getProposals(
            @RequestParam(required = false) String status,
            Pageable pageable) {

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

    @GetMapping("/proposals/{id}")
    public ResponseEntity<ProposalDetailDTO> getProposalDetail(@PathVariable Long id) {
                
        try {
            PolicyEvolutionProposal proposal = proposalRepository.findById(id)
                .orElse(null);
            
            if (proposal == null) {
                return ResponseEntity.notFound().build();
            }
            
            ProposalDetailDTO dto = toDetailDTO(proposal);

            PolicyApprovalService.ApprovalHistory history = approvalService.getApprovalHistory(id);
            dto.setApprovalHistory(history);
            
            return ResponseEntity.ok(dto);
            
        } catch (Exception e) {
            log.error("Error fetching proposal detail", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PostMapping("/proposals/{id}/approve")
    public ResponseEntity<ApprovalResponseDTO> approveProposal(
            @PathVariable Long id,
            @Valid @RequestBody ApprovalRequestDTO request) {

        try {
            
            if (request.getRequestId() == null) {
                log.error("Approval request ID is required. Governance bypass attempt blocked: proposalId={}", id);
                ApprovalResponseDTO response = ApprovalResponseDTO.builder()
                    .proposalId(id)
                    .success(false)
                    .message("Approval request ID (requestId) is required. Please use the governance process to approve.")
                    .timestamp(LocalDateTime.now())
                    .build();
                return ResponseEntity.badRequest().body(response);
            }

            PolicyApprovalService.ApprovalWorkflow workflow = approvalService.findWorkflowByProposalId(id);
            if (workflow == null || workflow.getRequest(request.getRequestId()) == null) {
                log.error("Request does not belong to proposal: requestId={}, proposalId={}", request.getRequestId(), id);
                return ResponseEntity.badRequest().body(
                    ApprovalResponseDTO.builder()
                        .proposalId(id)
                        .success(false)
                        .message("Request does not belong to this proposal")
                        .timestamp(LocalDateTime.now())
                        .build());
            }

            PolicyApprovalService.ApprovalResult result = approvalService.processApproval(
                request.getRequestId(),
                request.getApproverId(),
                PolicyApprovalService.ApprovalDecision.APPROVE,
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

    @PostMapping("/proposals/{id}/reject")
    public ResponseEntity<ApprovalResponseDTO> rejectProposal(
            @PathVariable Long id,
            @Valid @RequestBody ApprovalRequestDTO request) {

        try {
            
            if (request.getRequestId() == null) {
                log.error("Approval request ID is required. Governance bypass attempt blocked: proposalId={}", id);
                ApprovalResponseDTO response = ApprovalResponseDTO.builder()
                    .proposalId(id)
                    .success(false)
                    .message("Approval request ID (requestId) is required. Please use the governance process to reject.")
                    .timestamp(LocalDateTime.now())
                    .build();
                return ResponseEntity.badRequest().body(response);
            }

            PolicyApprovalService.ApprovalWorkflow workflow = approvalService.findWorkflowByProposalId(id);
            if (workflow == null || workflow.getRequest(request.getRequestId()) == null) {
                log.error("Request does not belong to proposal: requestId={}, proposalId={}", request.getRequestId(), id);
                return ResponseEntity.badRequest().body(
                    ApprovalResponseDTO.builder()
                        .proposalId(id)
                        .success(false)
                        .message("Request does not belong to this proposal")
                        .timestamp(LocalDateTime.now())
                        .build());
            }

            PolicyApprovalService.ApprovalResult result = approvalService.processApproval(
                request.getRequestId(),
                request.getApproverId(),
                PolicyApprovalService.ApprovalDecision.REJECT,
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

    @PostMapping("/proposals/{id}/evaluate")
    public ResponseEntity<ImpactAnalysisDTO> evaluateProposal(@PathVariable Long id) {
                
        try {
            PolicyEvolutionProposal proposal = proposalRepository.findById(id)
                .orElse(null);
            
            if (proposal == null) {
                return ResponseEntity.notFound().build();
            }

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

    @GetMapping("/analytics")
    public ResponseEntity<AnalyticsDTO> getAnalytics(
            @RequestParam(defaultValue = "WEEKLY") String period) {

        try {
            
            int days = 7; 
            if ("DAILY".equalsIgnoreCase(period)) {
                days = 1;
            } else if ("WEEKLY".equalsIgnoreCase(period)) {
                days = 7;
            } else if ("MONTHLY".equalsIgnoreCase(period)) {
                days = 30;
            }

            PolicyProposalAnalytics.DashboardStatistics stats = analyticsService.generateDashboardStatistics(days);

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

    @GetMapping("/active")
    public ResponseEntity<List<PolicyDTO>> getActivePolicies() {
                
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

    @PostMapping("/policies/{policyId}/deactivate")
    public ResponseEntity<PolicyOperationResultDTO> deactivatePolicy(
            @PathVariable Long policyId,
            @RequestBody DeactivationRequestDTO request) {

        try {
            
            SynthesisPolicyRepository.Policy policy = synthesisPolicyRepository.findById(policyId)
                .orElseThrow(() -> new IllegalArgumentException("Policy not found"));

            synthesisPolicyRepository.deactivate(policyId, request.getReason());

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

    @GetMapping("/approvals/pending")
    public ResponseEntity<List<PendingApprovalDTO>> getPendingApprovals(
            @RequestParam String approverId) {

        try {
            
            List<PolicyEvolutionProposal> pendingProposals = 
                proposalRepository.findByStatus(PolicyEvolutionProposal.ProposalStatus.PENDING);
            
            List<PendingApprovalDTO> pendingApprovals = pendingProposals.stream()
                .map(proposal -> {
                    PolicyApprovalService.ApprovalHistory history = 
                        approvalService.getApprovalHistory(proposal.getId());

                    return history.getRequests().stream()
                        .filter(req -> req.getApprover().getApproverId().equals(approverId))
                        .filter(req -> req.getStatus() == PolicyApprovalService.RequestStatus.PENDING)
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