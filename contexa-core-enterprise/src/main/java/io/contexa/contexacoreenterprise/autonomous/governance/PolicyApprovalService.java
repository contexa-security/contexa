package io.contexa.contexacoreenterprise.autonomous.governance;

import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.autonomous.PolicyActivationService;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalStatus;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.transaction.annotation.Transactional;

import java.io.Serializable;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class PolicyApprovalService {

    private final PolicyProposalRepository proposalRepository;
    private final ApplicationEventPublisher eventPublisher;

    @Autowired(required = false)
    private RedisTemplate<String, Object> redisTemplate;

    @Autowired(required = false)
    private PolicyActivationService policyActivationService;

    private static final Duration WORKFLOW_TTL = Duration.ofDays(7);

    private final Map<Long, ApprovalWorkflow> memoryWorkflows = new ConcurrentHashMap<>();

    private final Map<ApproverLevel, List<Approver>> approverPool = new ConcurrentHashMap<>();

    @Transactional
    public String initiateSingleApproval(Long proposalId, 
                                        PolicyEvolutionGovernance.RiskAssessment riskAssessment) {
                
        try {
            
            PolicyEvolutionProposal proposal = validateProposal(proposalId);

            Approver approver = selectApprover(ApproverLevel.STANDARD, riskAssessment);

            ApprovalWorkflow workflow = ApprovalWorkflow.builder()
                .workflowId(generateWorkflowId())
                .proposalId(proposalId)
                .workflowType(WorkflowType.SINGLE)
                .requiredApprovals(1)
                .approvers(List.of(approver))
                .riskAssessment(riskAssessment)
                .status(WorkflowStatus.PENDING)
                .createdAt(LocalDateTime.now())
                .build();

            ApprovalRequest request = createApprovalRequest(proposal, approver, workflow);
            workflow.addRequest(request);

            // Save after adding request so workflow is persisted in complete state
            saveWorkflow(proposalId, workflow);

            sendApprovalNotification(approver, request);

            publishApprovalEvent(ApprovalEventType.WORKFLOW_INITIATED, workflow);

            return workflow.getWorkflowId();
            
        } catch (Exception e) {
            log.error("Failed to initiate single approval for proposal: {}", proposalId, e);
            throw new ApprovalException("Single approval initiation failed", e);
        }
    }

    @Transactional
    public String initiateMultiApproval(Long proposalId, 
                                       int requiredApprovers,
                                       PolicyEvolutionGovernance.RiskAssessment riskAssessment) {
                
        try {
            
            PolicyEvolutionProposal proposal = validateProposal(proposalId);

            List<ApproverLevel> levels = determineApproverLevels(
                riskAssessment.getAdjustedRisk(), requiredApprovers);

            List<Approver> approvers = new ArrayList<>();
            for (ApproverLevel level : levels) {
                Approver approver = selectApprover(level, riskAssessment);
                approvers.add(approver);
            }

            ApprovalWorkflow workflow = ApprovalWorkflow.builder()
                .workflowId(generateWorkflowId())
                .proposalId(proposalId)
                .workflowType(WorkflowType.MULTI_LEVEL)
                .requiredApprovals(requiredApprovers)
                .approvers(approvers)
                .approverLevels(levels)
                .riskAssessment(riskAssessment)
                .status(WorkflowStatus.PENDING)
                .createdAt(LocalDateTime.now())
                .build();

            saveWorkflow(proposalId, workflow);

            Approver firstApprover = approvers.get(0);
            ApprovalRequest firstRequest = createApprovalRequest(proposal, firstApprover, workflow);
            workflow.addRequest(firstRequest);

            sendApprovalNotification(firstApprover, firstRequest);

            publishApprovalEvent(ApprovalEventType.WORKFLOW_INITIATED, workflow);

            return workflow.getWorkflowId();
            
        } catch (Exception e) {
            log.error("Failed to initiate multi-level approval for proposal: {}", proposalId, e);
            throw new ApprovalException("Multi-level approval initiation failed", e);
        }
    }

    @Transactional
    public ApprovalResult processApproval(String requestId, String approverId, 
                                         ApprovalDecision decision, String comments) {
                
        try {
            
            ApprovalWorkflow workflow = findWorkflowByRequestId(requestId);
            if (workflow == null) {
                throw new ApprovalException("Workflow not found for request: " + requestId);
            }

            ApprovalRequest request = workflow.getRequest(requestId);
            if (request == null) {
                throw new ApprovalException("Request not found: " + requestId);
            }
            
            if (!request.getApprover().getApproverId().equals(approverId)) {
                throw new ApprovalException("Approver mismatch for request: " + requestId);
            }
            
            if (request.getStatus() != RequestStatus.PENDING) {
                throw new ApprovalException("Request is not pending: " + requestId);
            }

            request.setDecision(decision);
            request.setDecisionTime(LocalDateTime.now());
            request.setComments(comments);
            request.setStatus(decision == ApprovalDecision.APPROVE ? 
                RequestStatus.APPROVED : RequestStatus.REJECTED);

            boolean workflowComplete = updateWorkflowStatus(workflow, request);

            if (workflowComplete) {
                completeWorkflow(workflow);
            } else if (workflow.getWorkflowType() == WorkflowType.MULTI_LEVEL && 
                      decision == ApprovalDecision.APPROVE) {
                
                initiateNextApproval(workflow);
            }

            publishApprovalEvent(
                decision == ApprovalDecision.APPROVE ? 
                    ApprovalEventType.REQUEST_APPROVED : ApprovalEventType.REQUEST_REJECTED,
                workflow
            );

            ApprovalResult result = ApprovalResult.builder()
                .requestId(requestId)
                .workflowId(workflow.getWorkflowId())
                .decision(decision)
                .workflowComplete(workflowComplete)
                .workflowStatus(workflow.getStatus())
                .timestamp(LocalDateTime.now())
                .build();

            return result;
            
        } catch (Exception e) {
            log.error("Failed to process approval request: {}", requestId, e);
            throw new ApprovalException("Approval processing failed", e);
        }
    }

    public ApprovalHistory getApprovalHistory(Long proposalId) {
        
        ApprovalWorkflow workflow = getWorkflow(proposalId);
        if (workflow == null) {
            return ApprovalHistory.builder()
                .proposalId(proposalId)
                .requests(Collections.emptyList())
                .build();
        }
        
        return ApprovalHistory.builder()
            .proposalId(proposalId)
            .workflowId(workflow.getWorkflowId())
            .workflowType(workflow.getWorkflowType())
            .workflowStatus(workflow.getStatus())
            .requests(new ArrayList<>(workflow.getRequests()))
            .createdAt(workflow.getCreatedAt())
            .completedAt(workflow.getCompletedAt())
            .build();
    }

    public void registerApprover(Approver approver, ApproverLevel level) {
                
        approverPool.computeIfAbsent(level, k -> new ArrayList<>()).add(approver);
    }

    public void unregisterApprover(String approverId, ApproverLevel level) {
                
        List<Approver> approvers = approverPool.get(level);
        if (approvers != null) {
            approvers.removeIf(a -> a.getApproverId().equals(approverId));
        }
    }

    private PolicyEvolutionProposal validateProposal(Long proposalId) {
        PolicyEvolutionProposal proposal = proposalRepository.findById(proposalId)
            .orElseThrow(() -> new ApprovalException("Proposal not found: " + proposalId));
        
        if (proposal.getStatus() != ProposalStatus.PENDING && 
            proposal.getStatus() != ProposalStatus.APPROVED) {
            throw new ApprovalException("Proposal is not in valid state for approval: " + 
                proposal.getStatus());
        }
        
        return proposal;
    }
    
    private Approver selectApprover(ApproverLevel level, 
                                   PolicyEvolutionGovernance.RiskAssessment riskAssessment) {
        List<Approver> availableApprovers = approverPool.get(level);
        
        if (availableApprovers == null || availableApprovers.isEmpty()) {
            log.error("No approver available for level: {}", level);
            throw new IllegalStateException("No approver available for level: " + level);
        }

        return availableApprovers.stream()
            .min(Comparator.comparing(Approver::getCurrentWorkload))
            .orElse(createDefaultApprover(level));
    }
    
    private Approver createDefaultApprover(ApproverLevel level) {
        return Approver.builder()
            .approverId("DEFAULT_" + level.name())
            .name("Default " + level.name() + " Approver")
            .email("approver@contexa.com")
            .level(level)
            .currentWorkload(0)
            .build();
    }
    
    private List<ApproverLevel> determineApproverLevels(
            PolicyEvolutionProposal.RiskLevel riskLevel, int requiredApprovers) {
        
        List<ApproverLevel> levels = new ArrayList<>();
        
        if (riskLevel == PolicyEvolutionProposal.RiskLevel.CRITICAL) {
            levels.add(ApproverLevel.EXECUTIVE);
            if (requiredApprovers > 1) levels.add(ApproverLevel.SENIOR);
            if (requiredApprovers > 2) levels.add(ApproverLevel.STANDARD);
        } else if (riskLevel == PolicyEvolutionProposal.RiskLevel.HIGH) {
            levels.add(ApproverLevel.SENIOR);
            if (requiredApprovers > 1) levels.add(ApproverLevel.STANDARD);
        } else {
            for (int i = 0; i < requiredApprovers; i++) {
                levels.add(ApproverLevel.STANDARD);
            }
        }
        
        return levels;
    }
    
    private ApprovalRequest createApprovalRequest(PolicyEvolutionProposal proposal, 
                                                 Approver approver, 
                                                 ApprovalWorkflow workflow) {
        return ApprovalRequest.builder()
            .requestId(generateRequestId())
            .workflowId(workflow.getWorkflowId())
            .proposalId(proposal.getId())
            .approver(approver)
            .status(RequestStatus.PENDING)
            .createdAt(LocalDateTime.now())
            .expiresAt(LocalDateTime.now().plusDays(3))
            .proposalSummary(createProposalSummary(proposal))
            .riskSummary(workflow.getRiskAssessment())
            .build();
    }
    
    private Map<String, Object> createProposalSummary(PolicyEvolutionProposal proposal) {
        Map<String, Object> summary = new HashMap<>();
        summary.put("title", proposal.getTitle());
        summary.put("type", proposal.getProposalType());
        summary.put("risk", proposal.getRiskLevel());
        summary.put("confidence", proposal.getConfidenceScore());
        summary.put("expectedImpact", proposal.getExpectedImpact());
        summary.put("aiReasoning", proposal.getAiReasoning());
        return summary;
    }
    
    @Async
    private void sendApprovalNotification(Approver approver, ApprovalRequest request) {

        NotificationEvent event = NotificationEvent.builder()
            .recipientId(approver.getApproverId())
            .recipientEmail(approver.getEmail())
            .type(NotificationType.APPROVAL_REQUEST)
            .requestId(request.getRequestId())
            .proposalId(request.getProposalId())
            .message(String.format("Approval required for proposal %d", request.getProposalId()))
            .timestamp(LocalDateTime.now())
            .build();
        
        eventPublisher.publishEvent(event);
    }
    
    private boolean updateWorkflowStatus(ApprovalWorkflow workflow, ApprovalRequest request) {
        if (request.getDecision() == ApprovalDecision.REJECT) {
            workflow.setStatus(WorkflowStatus.REJECTED);
            workflow.setCompletedAt(LocalDateTime.now());
            return true;
        }

        long approvedCount = workflow.getRequests().stream()
            .filter(r -> r.getStatus() == RequestStatus.APPROVED)
            .count();
        
        if (approvedCount >= workflow.getRequiredApprovals()) {
            workflow.setStatus(WorkflowStatus.APPROVED);
            workflow.setCompletedAt(LocalDateTime.now());
            return true;
        }
        
        return false;
    }
    
    private void completeWorkflow(ApprovalWorkflow workflow) {
                
        PolicyEvolutionProposal proposal = proposalRepository.findById(workflow.getProposalId())
            .orElseThrow(() -> new ApprovalException("Proposal not found"));
        
        if (workflow.getStatus() == WorkflowStatus.APPROVED) {
            
            proposal.setStatus(ProposalStatus.APPROVED);
            proposal.setApprovedBy(collectApprovers(workflow));
            proposal.setReviewedAt(LocalDateTime.now());
            proposalRepository.save(proposal);

            if (policyActivationService != null) {
                policyActivationService.activatePolicy(workflow.getProposalId(), proposal.getApprovedBy());
            } else {
                log.error("PolicyActivationService not available - policy activation skipped");
            }
        } else if (workflow.getStatus() == WorkflowStatus.REJECTED) {
            
            proposal.setStatus(ProposalStatus.REJECTED);
            proposal.setRejectionReason(collectRejectionReasons(workflow));
            proposal.setReviewedAt(LocalDateTime.now());
            proposalRepository.save(proposal);
        }

        removeWorkflow(workflow.getProposalId());
    }
    
    private void initiateNextApproval(ApprovalWorkflow workflow) {
        long approvedCount = workflow.getRequests().stream()
            .filter(r -> r.getStatus() == RequestStatus.APPROVED)
            .count();
        
        if (approvedCount < workflow.getApprovers().size()) {
            Approver nextApprover = workflow.getApprovers().get((int) approvedCount);
            PolicyEvolutionProposal proposal = proposalRepository.findById(workflow.getProposalId())
                .orElseThrow(() -> new ApprovalException("Proposal not found"));
            
            ApprovalRequest nextRequest = createApprovalRequest(proposal, nextApprover, workflow);
            workflow.addRequest(nextRequest);
            sendApprovalNotification(nextApprover, nextRequest);
        }
    }
    
    private ApprovalWorkflow findWorkflowByRequestId(String requestId) {
        
        if (isRedisAvailable()) {
            try {
                String requestKey = ZeroTrustRedisKeys.approvalRequest(requestId);
                Object proposalIdObj = redisTemplate.opsForValue().get(requestKey);
                if (proposalIdObj != null) {
                    Long proposalId = Long.valueOf(proposalIdObj.toString());
                    return getWorkflow(proposalId);
                }
            } catch (Exception e) {
                log.error("Redis request ID lookup failed, falling back to full search: {}", e.getMessage());
            }
        }

        return getAllWorkflows().stream()
            .filter(w -> w.getRequests().stream()
                .anyMatch(r -> r.getRequestId().equals(requestId)))
            .findFirst()
            .orElse(null);
    }
    
    private String collectApprovers(ApprovalWorkflow workflow) {
        return workflow.getRequests().stream()
            .filter(r -> r.getStatus() == RequestStatus.APPROVED)
            .map(r -> r.getApprover().getName())
            .collect(Collectors.joining(", "));
    }
    
    private String collectRejectionReasons(ApprovalWorkflow workflow) {
        return workflow.getRequests().stream()
            .filter(r -> r.getStatus() == RequestStatus.REJECTED)
            .map(r -> r.getComments())
            .filter(Objects::nonNull)
            .collect(Collectors.joining("; "));
    }
    
    private void publishApprovalEvent(ApprovalEventType type, ApprovalWorkflow workflow) {
        ApprovalEvent event = ApprovalEvent.builder()
            .eventType(type)
            .workflowId(workflow.getWorkflowId())
            .proposalId(workflow.getProposalId())
            .workflowStatus(workflow.getStatus())
            .timestamp(LocalDateTime.now())
            .build();
        
        eventPublisher.publishEvent(event);
    }
    
    private String generateWorkflowId() {
        return "WF_" + System.currentTimeMillis() + "_" + UUID.randomUUID().toString().substring(0, 8);
    }
    
    private String generateRequestId() {
        return "REQ_" + System.currentTimeMillis() + "_" + UUID.randomUUID().toString().substring(0, 8);
    }

    private boolean isRedisAvailable() {
        return redisTemplate != null;
    }

    private void saveWorkflow(Long proposalId, ApprovalWorkflow workflow) {
        if (isRedisAvailable()) {
            try {
                
                String key = ZeroTrustRedisKeys.approvalWorkflow(proposalId);
                redisTemplate.opsForValue().set(key, workflow, WORKFLOW_TTL);

                String indexKey = ZeroTrustRedisKeys.approvalWorkflowIndex();
                redisTemplate.opsForSet().add(indexKey, proposalId);

                for (ApprovalRequest request : workflow.getRequests()) {
                    String requestKey = ZeroTrustRedisKeys.approvalRequest(request.getRequestId());
                    redisTemplate.opsForValue().set(requestKey, proposalId, WORKFLOW_TTL);
                }

                            } catch (Exception e) {
                log.error("Redis save failed, memory fallback: {}", e.getMessage());
                memoryWorkflows.put(proposalId, workflow);
            }
        } else {
            memoryWorkflows.put(proposalId, workflow);
        }
    }

    private ApprovalWorkflow getWorkflow(Long proposalId) {
        if (isRedisAvailable()) {
            try {
                String key = ZeroTrustRedisKeys.approvalWorkflow(proposalId);
                Object obj = redisTemplate.opsForValue().get(key);
                if (obj instanceof ApprovalWorkflow) {
                    return (ApprovalWorkflow) obj;
                }
            } catch (Exception e) {
                log.error("Redis lookup failed, memory fallback: {}", e.getMessage());
            }
        }
        return memoryWorkflows.get(proposalId);
    }

    private void removeWorkflow(Long proposalId) {
        if (isRedisAvailable()) {
            try {
                
                ApprovalWorkflow workflow = getWorkflow(proposalId);
                if (workflow != null) {
                    for (ApprovalRequest request : workflow.getRequests()) {
                        String requestKey = ZeroTrustRedisKeys.approvalRequest(request.getRequestId());
                        redisTemplate.delete(requestKey);
                    }
                }

                String key = ZeroTrustRedisKeys.approvalWorkflow(proposalId);
                redisTemplate.delete(key);

                String indexKey = ZeroTrustRedisKeys.approvalWorkflowIndex();
                redisTemplate.opsForSet().remove(indexKey, proposalId);

                            } catch (Exception e) {
                log.error("Redis delete failed: {}", e.getMessage());
            }
        }
        memoryWorkflows.remove(proposalId);
    }

    private List<ApprovalWorkflow> getAllWorkflows() {
        List<ApprovalWorkflow> workflows = new ArrayList<>();

        if (isRedisAvailable()) {
            try {
                String indexKey = ZeroTrustRedisKeys.approvalWorkflowIndex();
                Set<Object> proposalIds = redisTemplate.opsForSet().members(indexKey);
                if (proposalIds != null) {
                    for (Object proposalIdObj : proposalIds) {
                        Long proposalId = Long.valueOf(proposalIdObj.toString());
                        ApprovalWorkflow workflow = getWorkflow(proposalId);
                        if (workflow != null) {
                            workflows.add(workflow);
                        }
                    }
                }
            } catch (Exception e) {
                log.error("Redis full query failed, memory fallback: {}", e.getMessage());
                workflows.addAll(memoryWorkflows.values());
            }
        } else {
            workflows.addAll(memoryWorkflows.values());
        }

        return workflows;
    }

    @lombok.Builder
    @lombok.Data
    public static class ApprovalWorkflow implements Serializable {
        private static final long serialVersionUID = 1L;
        private String workflowId;
        private Long proposalId;
        private WorkflowType workflowType;
        private int requiredApprovals;
        private List<Approver> approvers;
        private List<ApproverLevel> approverLevels;
        @lombok.Builder.Default
        private List<ApprovalRequest> requests = new ArrayList<>();
        private PolicyEvolutionGovernance.RiskAssessment riskAssessment;
        private WorkflowStatus status;
        private LocalDateTime createdAt;
        private LocalDateTime completedAt;
        
        public void addRequest(ApprovalRequest request) {
            requests.add(request);
        }
        
        public ApprovalRequest getRequest(String requestId) {
            return requests.stream()
                .filter(r -> r.getRequestId().equals(requestId))
                .findFirst()
                .orElse(null);
        }
    }

    @lombok.Builder
    @lombok.Data
    public static class ApprovalRequest implements Serializable {
        private static final long serialVersionUID = 1L;
        private String requestId;
        private String workflowId;
        private Long proposalId;
        private Approver approver;
        private RequestStatus status;
        private ApprovalDecision decision;
        private String comments;
        private LocalDateTime createdAt;
        private LocalDateTime expiresAt;
        private LocalDateTime decisionTime;
        private Map<String, Object> proposalSummary;
        private PolicyEvolutionGovernance.RiskAssessment riskSummary;
    }

    @lombok.Builder
    @lombok.Data
    public static class Approver implements Serializable {
        private static final long serialVersionUID = 1L;
        private String approverId;
        private String name;
        private String email;
        private ApproverLevel level;
        private int currentWorkload;
    }

    @lombok.Builder
    @lombok.Data
    public static class ApprovalResult {
        private String requestId;
        private String workflowId;
        private ApprovalDecision decision;
        private boolean workflowComplete;
        private WorkflowStatus workflowStatus;
        private LocalDateTime timestamp;
    }

    @lombok.Builder
    @lombok.Data
    public static class ApprovalHistory {
        private Long proposalId;
        private String workflowId;
        private WorkflowType workflowType;
        private WorkflowStatus workflowStatus;
        private List<ApprovalRequest> requests;
        private LocalDateTime createdAt;
        private LocalDateTime completedAt;
    }

    public enum WorkflowType {
        SINGLE,
        MULTI_LEVEL,
        PARALLEL,
        SEQUENTIAL
    }

    public enum WorkflowStatus {
        PENDING,
        IN_PROGRESS,
        APPROVED,
        REJECTED,
        EXPIRED,
        CANCELLED
    }

    public enum RequestStatus {
        PENDING,
        APPROVED,
        REJECTED,
        EXPIRED,
        CANCELLED
    }

    public enum ApprovalDecision {
        APPROVE,
        REJECT,
        DEFER
    }

    public enum ApproverLevel {
        STANDARD,
        SENIOR,
        EXECUTIVE
    }

    public enum ApprovalEventType {
        WORKFLOW_INITIATED,
        REQUEST_CREATED,
        REQUEST_APPROVED,
        REQUEST_REJECTED,
        WORKFLOW_COMPLETED,
        WORKFLOW_CANCELLED
    }

    @lombok.Builder
    @lombok.Data
    public static class ApprovalEvent {
        private ApprovalEventType eventType;
        private String workflowId;
        private Long proposalId;
        private WorkflowStatus workflowStatus;
        private LocalDateTime timestamp;
    }

    @lombok.Builder
    @lombok.Data
    public static class NotificationEvent {
        private String recipientId;
        private String recipientEmail;
        private NotificationType type;
        private String requestId;
        private Long proposalId;
        private String message;
        private LocalDateTime timestamp;
    }

    public enum NotificationType {
        APPROVAL_REQUEST,
        APPROVAL_REMINDER,
        APPROVAL_COMPLETE,
        APPROVAL_REJECTED
    }

    public static class ApprovalException extends RuntimeException {
        public ApprovalException(String message) {
            super(message);
        }
        
        public ApprovalException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}