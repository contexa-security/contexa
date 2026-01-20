package io.contexa.contexacoreenterprise.autonomous;

import io.contexa.contexacore.autonomous.IPolicyProposalManagementService;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalStatus;
import io.contexa.contexacoreenterprise.autonomous.governance.PolicyEvolutionGovernance;
import io.contexa.contexacoreenterprise.autonomous.governance.PolicyEvolutionGovernance.GovernanceDecision;
import io.contexa.contexacore.repository.PolicyEvolutionProposalRepository;
import io.contexa.contexacoreenterprise.autonomous.monitor.PolicyAuditLogger;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;


@Slf4j
@RequiredArgsConstructor
public class PolicyProposalManagementService implements IPolicyProposalManagementService {
    
    private final PolicyEvolutionProposalRepository proposalRepository;
    private final PolicyEvolutionGovernance governance;
    private final PolicyAuditLogger auditLogger;
    private final ApplicationEventPublisher eventPublisher;
    
    
    @Transactional
    public Long submitProposal(PolicyEvolutionProposal proposal) {
        log.info("Submitting policy evolution proposal: {}", proposal.getTitle());
        
        
        if (proposal.getStatus() == null) {
            proposal.setStatus(ProposalStatus.DRAFT);
        }
        
        if (proposal.getCreatedAt() == null) {
            proposal.setCreatedAt(LocalDateTime.now());
        }
        
        
        if (proposal.getMetadata() == null) {
            proposal.setMetadata(new HashMap<>());
        }
        
        
        PolicyEvolutionProposal savedProposal = proposalRepository.save(proposal);
        
        
        Map<String, Object> context = new HashMap<>();
        context.put("title", proposal.getTitle());
        context.put("riskLevel", proposal.getRiskLevel());
        context.put("proposalType", proposal.getProposalType());
        auditLogger.logPolicyCreation(savedProposal.getId(), proposal.getCreatedBy(), context);
        
        
        CompletableFuture.runAsync(() -> evaluateProposal(savedProposal.getId()));
        
        
        publishProposalCreatedEvent(savedProposal);
        
        return savedProposal.getId();
    }
    
    
    public void evaluateProposal(Long proposalId) {
        log.info("Evaluating proposal: {}", proposalId);
        
        try {
            Optional<PolicyEvolutionProposal> optionalProposal = proposalRepository.findById(proposalId);
            if (optionalProposal.isEmpty()) {
                log.error("Proposal not found: {}", proposalId);
                return;
            }
            
            PolicyEvolutionProposal proposal = optionalProposal.get();
            
            
            GovernanceDecision decision = governance.evaluateProposal(proposalId);
            
            
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
            
            
            proposalRepository.save(proposal);
            
            
            publishProposalEvaluatedEvent(proposal, decision);
            
        } catch (Exception e) {
            log.error("Error evaluating proposal {}", proposalId, e);
        }
    }
    
    
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
        
        
        Map<String, Object> context = new HashMap<>();
        context.put("proposalId", proposalId);
        auditLogger.logPolicyApproval(proposalId, approvedBy, "MANUAL", context);
        
        
        publishProposalApprovedEvent(proposal);
    }
    
    
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
        
        
        Map<String, Object> context = new HashMap<>();
        context.put("proposalId", proposalId);
        context.put("reason", reason);
        auditLogger.logPolicyRejection(proposalId, rejectedBy, reason, context);
        
        
        publishProposalRejectedEvent(proposal);
    }
    
    
    public Optional<PolicyEvolutionProposal> getProposal(Long proposalId) {
        return proposalRepository.findById(proposalId);
    }
    
    
    public List<PolicyEvolutionProposal> getAllProposals() {
        return proposalRepository.findAll();
    }
    
    
    public List<PolicyEvolutionProposal> getPendingProposals() {
        return proposalRepository.findByStatus(ProposalStatus.PENDING_APPROVAL);
    }
    
    
    public List<PolicyEvolutionProposal> getProposalsByStatus(ProposalStatus status) {
        return proposalRepository.findByStatus(status);
    }
    
    
    @Transactional
    public PolicyEvolutionProposal updateProposal(Long proposalId, PolicyEvolutionProposal updates) {
        Optional<PolicyEvolutionProposal> optionalProposal = proposalRepository.findById(proposalId);
        if (optionalProposal.isEmpty()) {
            throw new IllegalArgumentException("Proposal not found: " + proposalId);
        }
        
        PolicyEvolutionProposal existing = optionalProposal.get();
        
        
        if (existing.getStatus() != ProposalStatus.DRAFT && 
            existing.getStatus() != ProposalStatus.PENDING_APPROVAL) {
            throw new IllegalStateException("Cannot update proposal in status: " + existing.getStatus());
        }
        
        
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
    
    
    @Transactional
    public void deleteProposal(Long proposalId) {
        Optional<PolicyEvolutionProposal> optionalProposal = proposalRepository.findById(proposalId);
        if (optionalProposal.isEmpty()) {
            throw new IllegalArgumentException("Proposal not found: " + proposalId);
        }
        
        PolicyEvolutionProposal proposal = optionalProposal.get();
        
        
        if (proposal.getStatus() == ProposalStatus.APPROVED && proposal.getPolicyId() != null) {
            throw new IllegalStateException("Cannot delete approved and activated proposal");
        }

        proposalRepository.deleteById(proposalId);

        log.info("Deleted proposal: {}", proposalId);
    }
    
    
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
        
        
        public Object getSource() { return source; }
        public EventType getEventType() { return eventType; }
        public PolicyEvolutionProposal getProposal() { return proposal; }
        public LocalDateTime getTimestamp() { return timestamp; }
        public GovernanceDecision getDecision() { return decision; }
        public void setDecision(GovernanceDecision decision) { this.decision = decision; }
    }
}