package io.contexa.contexacore.autonomous.governance;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalStatus;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import io.contexa.contexacore.autonomous.evolution.PolicyActivationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * 승인 서비스
 * 
 * 정책 제안에 대한 단일 및 다단계 승인 워크플로우를 관리합니다.
 * 승인자 관리, 알림, 이력 추적 기능을 제공합니다.
 * 
 * @author AI3Security
 * @since 1.0.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ApprovalService {
    
    private final PolicyProposalRepository proposalRepository;
    private final PolicyActivationService activationService;
    private final ApplicationEventPublisher eventPublisher;
    
    // 승인 워크플로우 저장소
    private final Map<Long, ApprovalWorkflow> activeWorkflows = new ConcurrentHashMap<>();
    
    // 승인자 풀
    private final Map<ApproverLevel, List<Approver>> approverPool = new ConcurrentHashMap<>();
    
    /**
     * 단일 승인 프로세스 시작
     * 
     * @param proposalId 제안 ID
     * @param riskAssessment 위험 평가
     * @return 워크플로우 ID
     */
    @Transactional
    public String initiateSingleApproval(Long proposalId, 
                                        PolicyEvolutionGovernance.RiskAssessment riskAssessment) {
        log.info("Initiating single approval for proposal: {}", proposalId);
        
        try {
            // 1. 제안 검증
            PolicyEvolutionProposal proposal = validateProposal(proposalId);
            
            // 2. 승인자 선택
            Approver approver = selectApprover(ApproverLevel.STANDARD, riskAssessment);
            
            // 3. 워크플로우 생성
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
            
            // 4. 워크플로우 저장
            activeWorkflows.put(proposalId, workflow);
            
            // 5. 승인 요청 생성
            ApprovalRequest request = createApprovalRequest(proposal, approver, workflow);
            workflow.addRequest(request);
            
            // 6. 알림 발송
            sendApprovalNotification(approver, request);
            
            // 7. 이벤트 발행
            publishApprovalEvent(ApprovalEventType.WORKFLOW_INITIATED, workflow);
            
            log.info("Single approval workflow {} initiated for proposal {}", 
                workflow.getWorkflowId(), proposalId);
            
            return workflow.getWorkflowId();
            
        } catch (Exception e) {
            log.error("Failed to initiate single approval for proposal: {}", proposalId, e);
            throw new ApprovalException("Single approval initiation failed", e);
        }
    }
    
    /**
     * 다단계 승인 프로세스 시작
     * 
     * @param proposalId 제안 ID
     * @param requiredApprovers 필요한 승인자 수
     * @param riskAssessment 위험 평가
     * @return 워크플로우 ID
     */
    @Transactional
    public String initiateMultiApproval(Long proposalId, 
                                       int requiredApprovers,
                                       PolicyEvolutionGovernance.RiskAssessment riskAssessment) {
        log.info("Initiating multi-level approval for proposal: {} with {} approvers", 
            proposalId, requiredApprovers);
        
        try {
            // 1. 제안 검증
            PolicyEvolutionProposal proposal = validateProposal(proposalId);
            
            // 2. 승인자 레벨 결정
            List<ApproverLevel> levels = determineApproverLevels(
                riskAssessment.getAdjustedRisk(), requiredApprovers);
            
            // 3. 승인자 선택
            List<Approver> approvers = new ArrayList<>();
            for (ApproverLevel level : levels) {
                Approver approver = selectApprover(level, riskAssessment);
                approvers.add(approver);
            }
            
            // 4. 워크플로우 생성
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
            
            // 5. 워크플로우 저장
            activeWorkflows.put(proposalId, workflow);
            
            // 6. 첫 번째 승인자에게 요청 생성
            Approver firstApprover = approvers.get(0);
            ApprovalRequest firstRequest = createApprovalRequest(proposal, firstApprover, workflow);
            workflow.addRequest(firstRequest);
            
            // 7. 알림 발송
            sendApprovalNotification(firstApprover, firstRequest);
            
            // 8. 이벤트 발행
            publishApprovalEvent(ApprovalEventType.WORKFLOW_INITIATED, workflow);
            
            log.info("Multi-level approval workflow {} initiated for proposal {}", 
                workflow.getWorkflowId(), proposalId);
            
            return workflow.getWorkflowId();
            
        } catch (Exception e) {
            log.error("Failed to initiate multi-level approval for proposal: {}", proposalId, e);
            throw new ApprovalException("Multi-level approval initiation failed", e);
        }
    }
    
    /**
     * 승인 처리
     * 
     * @param requestId 요청 ID
     * @param approverId 승인자 ID
     * @param decision 승인 결정
     * @param comments 코멘트
     * @return 처리 결과
     */
    @Transactional
    public ApprovalResult processApproval(String requestId, String approverId, 
                                         ApprovalDecision decision, String comments) {
        log.info("Processing approval request {} by approver {}: {}", 
            requestId, approverId, decision);
        
        try {
            // 1. 워크플로우 찾기
            ApprovalWorkflow workflow = findWorkflowByRequestId(requestId);
            if (workflow == null) {
                throw new ApprovalException("Workflow not found for request: " + requestId);
            }
            
            // 2. 요청 찾기 및 검증
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
            
            // 3. 승인 기록
            request.setDecision(decision);
            request.setDecisionTime(LocalDateTime.now());
            request.setComments(comments);
            request.setStatus(decision == ApprovalDecision.APPROVE ? 
                RequestStatus.APPROVED : RequestStatus.REJECTED);
            
            // 4. 워크플로우 업데이트
            boolean workflowComplete = updateWorkflowStatus(workflow, request);
            
            // 5. 제안 상태 업데이트
            if (workflowComplete) {
                completeWorkflow(workflow);
            } else if (workflow.getWorkflowType() == WorkflowType.MULTI_LEVEL && 
                      decision == ApprovalDecision.APPROVE) {
                // 다음 승인자에게 요청
                initiateNextApproval(workflow);
            }
            
            // 6. 이벤트 발행
            publishApprovalEvent(
                decision == ApprovalDecision.APPROVE ? 
                    ApprovalEventType.REQUEST_APPROVED : ApprovalEventType.REQUEST_REJECTED,
                workflow
            );
            
            // 7. 결과 생성
            ApprovalResult result = ApprovalResult.builder()
                .requestId(requestId)
                .workflowId(workflow.getWorkflowId())
                .decision(decision)
                .workflowComplete(workflowComplete)
                .workflowStatus(workflow.getStatus())
                .timestamp(LocalDateTime.now())
                .build();
            
            log.info("Approval request {} processed. Workflow complete: {}", 
                requestId, workflowComplete);
            
            return result;
            
        } catch (Exception e) {
            log.error("Failed to process approval request: {}", requestId, e);
            throw new ApprovalException("Approval processing failed", e);
        }
    }
    
    /**
     * 승인 이력 조회
     * 
     * @param proposalId 제안 ID
     * @return 승인 이력
     */
    public ApprovalHistory getApprovalHistory(Long proposalId) {
        log.debug("Retrieving approval history for proposal: {}", proposalId);
        
        ApprovalWorkflow workflow = activeWorkflows.get(proposalId);
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
    
    /**
     * 승인자 등록
     * 
     * @param approver 승인자
     * @param level 승인자 레벨
     */
    public void registerApprover(Approver approver, ApproverLevel level) {
        log.info("Registering approver {} at level {}", approver.getApproverId(), level);
        
        approverPool.computeIfAbsent(level, k -> new ArrayList<>()).add(approver);
    }
    
    /**
     * 승인자 제거
     * 
     * @param approverId 승인자 ID
     * @param level 승인자 레벨
     */
    public void unregisterApprover(String approverId, ApproverLevel level) {
        log.info("Unregistering approver {} from level {}", approverId, level);
        
        List<Approver> approvers = approverPool.get(level);
        if (approvers != null) {
            approvers.removeIf(a -> a.getApproverId().equals(approverId));
        }
    }
    
    // ==================== Private Methods ====================
    
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
            // 기본 승인자 생성
            return createDefaultApprover(level);
        }
        
        // 가장 적은 워크로드를 가진 승인자 선택
        return availableApprovers.stream()
            .min(Comparator.comparing(Approver::getCurrentWorkload))
            .orElse(createDefaultApprover(level));
    }
    
    private Approver createDefaultApprover(ApproverLevel level) {
        return Approver.builder()
            .approverId("DEFAULT_" + level.name())
            .name("Default " + level.name() + " Approver")
            .email("approver@ai3security.com")
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
        log.info("Sending approval notification to {}", approver.getEmail());
        
        // 이메일 또는 기타 알림 시스템 통합
        // 실제 구현에서는 이메일 서비스나 알림 시스템을 사용
        
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
        
        // 승인된 요청 수 계산
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
        log.info("Completing workflow {} for proposal {}", 
            workflow.getWorkflowId(), workflow.getProposalId());
        
        PolicyEvolutionProposal proposal = proposalRepository.findById(workflow.getProposalId())
            .orElseThrow(() -> new ApprovalException("Proposal not found"));
        
        if (workflow.getStatus() == WorkflowStatus.APPROVED) {
            // 제안 승인
            proposal.setStatus(ProposalStatus.APPROVED);
            proposal.setApprovedBy(collectApprovers(workflow));
            proposal.setReviewedAt(LocalDateTime.now());
            proposalRepository.save(proposal);
            
            // 정책 활성화
            activationService.activatePolicy(workflow.getProposalId(), proposal.getApprovedBy());
        } else if (workflow.getStatus() == WorkflowStatus.REJECTED) {
            // 제안 거부
            proposal.setStatus(ProposalStatus.REJECTED);
            proposal.setRejectionReason(collectRejectionReasons(workflow));
            proposal.setReviewedAt(LocalDateTime.now());
            proposalRepository.save(proposal);
        }
        
        // 워크플로우 제거
        activeWorkflows.remove(workflow.getProposalId());
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
        return activeWorkflows.values().stream()
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
    
    // ==================== Inner Classes ====================
    
    /**
     * 승인 워크플로우
     */
    @lombok.Builder
    @lombok.Data
    public static class ApprovalWorkflow {
        private String workflowId;
        private Long proposalId;
        private WorkflowType workflowType;
        private int requiredApprovals;
        private List<Approver> approvers;
        private List<ApproverLevel> approverLevels;
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
    
    /**
     * 승인 요청
     */
    @lombok.Builder
    @lombok.Data
    public static class ApprovalRequest {
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
    
    /**
     * 승인자
     */
    @lombok.Builder
    @lombok.Data
    public static class Approver {
        private String approverId;
        private String name;
        private String email;
        private ApproverLevel level;
        private int currentWorkload;
    }
    
    /**
     * 승인 결과
     */
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
    
    /**
     * 승인 이력
     */
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
    
    /**
     * 워크플로우 타입
     */
    public enum WorkflowType {
        SINGLE,
        MULTI_LEVEL,
        PARALLEL,
        SEQUENTIAL
    }
    
    /**
     * 워크플로우 상태
     */
    public enum WorkflowStatus {
        PENDING,
        IN_PROGRESS,
        APPROVED,
        REJECTED,
        EXPIRED,
        CANCELLED
    }
    
    /**
     * 요청 상태
     */
    public enum RequestStatus {
        PENDING,
        APPROVED,
        REJECTED,
        EXPIRED,
        CANCELLED
    }
    
    /**
     * 승인 결정
     */
    public enum ApprovalDecision {
        APPROVE,
        REJECT,
        DEFER
    }
    
    /**
     * 승인자 레벨
     */
    public enum ApproverLevel {
        STANDARD,
        SENIOR,
        EXECUTIVE
    }
    
    /**
     * 승인 이벤트 타입
     */
    public enum ApprovalEventType {
        WORKFLOW_INITIATED,
        REQUEST_CREATED,
        REQUEST_APPROVED,
        REQUEST_REJECTED,
        WORKFLOW_COMPLETED,
        WORKFLOW_CANCELLED
    }
    
    /**
     * 승인 이벤트
     */
    @lombok.Builder
    @lombok.Data
    public static class ApprovalEvent {
        private ApprovalEventType eventType;
        private String workflowId;
        private Long proposalId;
        private WorkflowStatus workflowStatus;
        private LocalDateTime timestamp;
    }
    
    /**
     * 알림 이벤트
     */
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
    
    /**
     * 알림 타입
     */
    public enum NotificationType {
        APPROVAL_REQUEST,
        APPROVAL_REMINDER,
        APPROVAL_COMPLETE,
        APPROVAL_REJECTED
    }
    
    /**
     * 승인 예외
     */
    public static class ApprovalException extends RuntimeException {
        public ApprovalException(String message) {
            super(message);
        }
        
        public ApprovalException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}