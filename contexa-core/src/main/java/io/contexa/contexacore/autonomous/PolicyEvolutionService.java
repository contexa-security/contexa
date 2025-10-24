package io.contexa.contexacore.autonomous;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalStatus;
import io.contexa.contexacore.autonomous.governance.PolicyEvolutionGovernance;
import io.contexa.contexacore.autonomous.governance.PolicyEvolutionGovernance.GovernanceDecision;
import io.contexa.contexacore.autonomous.repository.PolicyEvolutionProposalRepository;
import io.contexa.contexacore.autonomous.monitor.PolicyAuditLogger;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * 정책 진화 서비스
 * 정책 제안의 생성, 평가, 승인, 활성화를 관리
 * 
 * @author AI3Security
 * @since 1.0.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PolicyEvolutionService {
    
    private final PolicyEvolutionProposalRepository proposalRepository;
    private final PolicyEvolutionGovernance governance;
    private final PolicyAuditLogger auditLogger;
    private final ApplicationEventPublisher eventPublisher;
    
    /**
     * 정책 제안 제출
     */
    @Transactional
    public Long submitProposal(PolicyEvolutionProposal proposal) {
        log.info("Submitting policy evolution proposal: {}", proposal.getTitle());
        
        // 기본값 설정
        if (proposal.getStatus() == null) {
            proposal.setStatus(ProposalStatus.DRAFT);
        }
        
        if (proposal.getCreatedAt() == null) {
            proposal.setCreatedAt(LocalDateTime.now());
        }
        
        // 메타데이터 초기화
        if (proposal.getMetadata() == null) {
            proposal.setMetadata(new HashMap<>());
        }
        
        // 저장
        PolicyEvolutionProposal savedProposal = proposalRepository.save(proposal);
        
        // 감사 로그
        Map<String, Object> context = new HashMap<>();
        context.put("title", proposal.getTitle());
        context.put("riskLevel", proposal.getRiskLevel());
        context.put("proposalType", proposal.getProposalType());
        auditLogger.logPolicyCreation(savedProposal.getId(), proposal.getCreatedBy(), context);
        
        // 거버넌스 평가 시작
        CompletableFuture.runAsync(() -> evaluateProposal(savedProposal.getId()));
        
        // 이벤트 발행
        publishProposalCreatedEvent(savedProposal);
        
        return savedProposal.getId();
    }
    
    /**
     * 제안 평가
     */
    public void evaluateProposal(Long proposalId) {
        log.info("Evaluating proposal: {}", proposalId);
        
        try {
            Optional<PolicyEvolutionProposal> optionalProposal = proposalRepository.findById(proposalId);
            if (optionalProposal.isEmpty()) {
                log.error("Proposal not found: {}", proposalId);
                return;
            }
            
            PolicyEvolutionProposal proposal = optionalProposal.get();
            
            // 거버넌스 평가
            GovernanceDecision decision = governance.evaluateProposal(proposalId);
            
            // 결정에 따른 상태 업데이트
            switch (decision.getDecision()) {
                case AUTO_APPROVE:
                    proposal.setStatus(ProposalStatus.APPROVED);
                    proposal.setApprovedAt(LocalDateTime.now());
                    proposal.setApprovedBy("AUTO_GOVERNANCE");
                    log.info("Proposal {} auto-approved", proposalId);
                    break;
                    
                case SINGLE_APPROVAL_REQUIRED:
                case MULTI_APPROVAL_REQUIRED:
                    proposal.setStatus(ProposalStatus.PENDING_APPROVAL);
                    log.info("Proposal {} requires manual approval", proposalId);
                    break;
                    
                case REJECT:
                    proposal.setStatus(ProposalStatus.REJECTED);
                    proposal.setRejectedAt(LocalDateTime.now());
                    proposal.setRejectedBy("AUTO_GOVERNANCE");
                    proposal.setRejectionReason(decision.getReason());
                    log.info("Proposal {} rejected: {}", proposalId, decision.getReason());
                    break;
                    
                case SKIP:
                    proposal.setStatus(ProposalStatus.DRAFT);
                    log.info("Proposal {} deferred for review", proposalId);
                    break;
            }
            
            // 저장
            proposalRepository.save(proposal);
            
            // 이벤트 발행
            publishProposalEvaluatedEvent(proposal, decision);
            
        } catch (Exception e) {
            log.error("Error evaluating proposal {}", proposalId, e);
        }
    }
    
    /**
     * 수동 승인
     */
    @Transactional
    public void approveProposal(Long proposalId, String approvedBy) {
        log.info("Manually approving proposal {} by {}", proposalId, approvedBy);
        
        Optional<PolicyEvolutionProposal> optionalProposal = proposalRepository.findById(proposalId);
        if (optionalProposal.isEmpty()) {
            throw new IllegalArgumentException("Proposal not found: " + proposalId);
        }
        
        PolicyEvolutionProposal proposal = optionalProposal.get();
        
        if (proposal.getStatus() != ProposalStatus.PENDING_APPROVAL) {
            throw new IllegalStateException("Proposal is not pending approval: " + proposal.getStatus());
        }
        
        proposal.setStatus(ProposalStatus.APPROVED);
        proposal.setApprovedAt(LocalDateTime.now());
        proposal.setApprovedBy(approvedBy);
        
        proposalRepository.save(proposal);
        
        // 감사 로그
        Map<String, Object> context = new HashMap<>();
        context.put("proposalId", proposalId);
        auditLogger.logPolicyApproval(proposalId, approvedBy, "MANUAL", context);
        
        // 이벤트 발행
        publishProposalApprovedEvent(proposal);
    }
    
    /**
     * 제안 거부
     */
    @Transactional
    public void rejectProposal(Long proposalId, String rejectedBy, String reason) {
        log.info("Rejecting proposal {} by {}: {}", proposalId, rejectedBy, reason);
        
        Optional<PolicyEvolutionProposal> optionalProposal = proposalRepository.findById(proposalId);
        if (optionalProposal.isEmpty()) {
            throw new IllegalArgumentException("Proposal not found: " + proposalId);
        }
        
        PolicyEvolutionProposal proposal = optionalProposal.get();
        
        if (proposal.getStatus() != ProposalStatus.PENDING_APPROVAL) {
            throw new IllegalStateException("Proposal is not pending approval: " + proposal.getStatus());
        }
        
        proposal.setStatus(ProposalStatus.REJECTED);
        proposal.setRejectedAt(LocalDateTime.now());
        proposal.setRejectedBy(rejectedBy);
        proposal.setRejectionReason(reason);
        
        proposalRepository.save(proposal);
        
        // 감사 로그
        Map<String, Object> context = new HashMap<>();
        context.put("proposalId", proposalId);
        context.put("reason", reason);
        auditLogger.logPolicyRejection(proposalId, rejectedBy, reason, context);
        
        // 이벤트 발행
        publishProposalRejectedEvent(proposal);
    }
    
    /**
     * 제안 조회
     */
    public Optional<PolicyEvolutionProposal> getProposal(Long proposalId) {
        return proposalRepository.findById(proposalId);
    }
    
    /**
     * 모든 제안 조회
     */
    public List<PolicyEvolutionProposal> getAllProposals() {
        return proposalRepository.findAll();
    }
    
    /**
     * 대기 중인 제안 조회
     */
    public List<PolicyEvolutionProposal> getPendingProposals() {
        return proposalRepository.findByStatus(ProposalStatus.PENDING_APPROVAL);
    }
    
    /**
     * 상태별 제안 조회
     */
    public List<PolicyEvolutionProposal> getProposalsByStatus(ProposalStatus status) {
        return proposalRepository.findByStatus(status);
    }
    
    /**
     * 제안 업데이트
     */
    @Transactional
    public PolicyEvolutionProposal updateProposal(Long proposalId, PolicyEvolutionProposal updates) {
        Optional<PolicyEvolutionProposal> optionalProposal = proposalRepository.findById(proposalId);
        if (optionalProposal.isEmpty()) {
            throw new IllegalArgumentException("Proposal not found: " + proposalId);
        }
        
        PolicyEvolutionProposal existing = optionalProposal.get();
        
        // 수정 가능한 상태 확인
        if (existing.getStatus() != ProposalStatus.DRAFT && 
            existing.getStatus() != ProposalStatus.PENDING_APPROVAL) {
            throw new IllegalStateException("Cannot update proposal in status: " + existing.getStatus());
        }
        
        // 업데이트
        if (updates.getTitle() != null) {
            existing.setTitle(updates.getTitle());
        }
        if (updates.getDescription() != null) {
            existing.setDescription(updates.getDescription());
        }
        if (updates.getRationale() != null) {
            existing.setRationale(updates.getRationale());
        }
        if (updates.getExpectedImpact() != null) {
            existing.setExpectedImpact(updates.getExpectedImpact());
        }
        if (updates.getPolicyContent() != null) {
            existing.setPolicyContent(updates.getPolicyContent());
        }
        
        return proposalRepository.save(existing);
    }
    
    /**
     * 제안 삭제
     */
    @Transactional
    public void deleteProposal(Long proposalId) {
        Optional<PolicyEvolutionProposal> optionalProposal = proposalRepository.findById(proposalId);
        if (optionalProposal.isEmpty()) {
            throw new IllegalArgumentException("Proposal not found: " + proposalId);
        }
        
        PolicyEvolutionProposal proposal = optionalProposal.get();
        
        // 삭제 가능한 상태 확인
        if (proposal.getStatus() == ProposalStatus.APPROVED && proposal.getPolicyId() != null) {
            throw new IllegalStateException("Cannot delete approved and activated proposal");
        }
        
        proposalRepository.delete(proposalId);
        
        log.info("Deleted proposal: {}", proposalId);
    }
    
    /**
     * 이벤트 발행 메서드들
     */
    private void publishProposalCreatedEvent(PolicyEvolutionProposal proposal) {
        ProposalEvent event = new ProposalEvent(this, ProposalEvent.EventType.CREATED, proposal);
        eventPublisher.publishEvent(event);
    }
    
    private void publishProposalEvaluatedEvent(PolicyEvolutionProposal proposal, GovernanceDecision decision) {
        ProposalEvent event = new ProposalEvent(this, ProposalEvent.EventType.EVALUATED, proposal);
        event.setDecision(decision);
        eventPublisher.publishEvent(event);
    }
    
    private void publishProposalApprovedEvent(PolicyEvolutionProposal proposal) {
        ProposalEvent event = new ProposalEvent(this, ProposalEvent.EventType.APPROVED, proposal);
        eventPublisher.publishEvent(event);
    }
    
    private void publishProposalRejectedEvent(PolicyEvolutionProposal proposal) {
        ProposalEvent event = new ProposalEvent(this, ProposalEvent.EventType.REJECTED, proposal);
        eventPublisher.publishEvent(event);
    }
    
    /**
     * 제안 이벤트
     */
    public static class ProposalEvent {
        public enum EventType {
            CREATED, EVALUATED, APPROVED, REJECTED, ACTIVATED
        }
        
        private final Object source;
        private final EventType eventType;
        private final PolicyEvolutionProposal proposal;
        private final LocalDateTime timestamp;
        private GovernanceDecision decision;
        
        public ProposalEvent(Object source, EventType eventType, PolicyEvolutionProposal proposal) {
            this.source = source;
            this.eventType = eventType;
            this.proposal = proposal;
            this.timestamp = LocalDateTime.now();
        }
        
        // Getters and Setters
        public Object getSource() { return source; }
        public EventType getEventType() { return eventType; }
        public PolicyEvolutionProposal getProposal() { return proposal; }
        public LocalDateTime getTimestamp() { return timestamp; }
        public GovernanceDecision getDecision() { return decision; }
        public void setDecision(GovernanceDecision decision) { this.decision = decision; }
    }
}