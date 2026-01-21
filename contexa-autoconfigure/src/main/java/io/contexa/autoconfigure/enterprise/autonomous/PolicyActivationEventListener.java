package io.contexa.autoconfigure.enterprise.autonomous;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import io.contexa.contexacoreenterprise.autonomous.evolution.PolicyActivationServiceImpl;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;


@Slf4j
@RequiredArgsConstructor
public class PolicyActivationEventListener {

    private final PolicyProposalRepository proposalRepository;
    private final ProposalToPolicyConverter proposalToPolicyConverter;
    private final PolicyService policyService;
    private final PolicyRetrievalPoint policyRetrievalPoint;
    private final CustomDynamicAuthorizationManager authorizationManager;

    
    @EventListener
    @Async
    @Transactional
    public void handlePolicyActivatedEvent(PolicyActivationServiceImpl.PolicyChangeEvent event) {
        if (event.getChangeType() != PolicyActivationServiceImpl.PolicyChangeType.ACTIVATED) {
            return;
        }

        Long proposalId = event.getProposalId();
        
        try {
            
            PolicyEvolutionProposal proposal = proposalRepository.findById(proposalId)
                    .orElseThrow(() -> new IllegalArgumentException(
                            "PolicyEvolutionProposal을 찾을 수 없습니다: proposalId=" + proposalId));

            
            if (proposal.getPolicyId() != null) {
                                
                reactivateExistingPolicy(proposal);
                return;
            }

            
            PolicyDto policyDto = proposalToPolicyConverter.convert(proposal);
            
            
            Policy savedPolicy = policyService.createPolicy(policyDto);
            
            
            updatePolicyForAIGenerated(savedPolicy, proposal);

            
            linkProposalToPolicy(proposal, savedPolicy);

            
            
        } catch (Exception e) {
            log.error("AI 정책 활성화 실패: proposalId={}, error={}",
                    proposalId, e.getMessage(), e);
            
            throw new RuntimeException("AI 정책 활성화 실패: " + e.getMessage(), e);
        }
    }

    
    @EventListener
    @Async
    @Transactional
    public void handlePolicyDeactivatedEvent(PolicyActivationServiceImpl.PolicyChangeEvent event) {
        if (event.getChangeType() != PolicyActivationServiceImpl.PolicyChangeType.DEACTIVATED) {
            return;
        }

        Long proposalId = event.getProposalId();
        
        try {
            PolicyEvolutionProposal proposal = proposalRepository.findById(proposalId)
                    .orElseThrow(() -> new IllegalArgumentException(
                            "PolicyEvolutionProposal을 찾을 수 없습니다: proposalId=" + proposalId));

            if (proposal.getPolicyId() != null) {
                
                deactivatePolicy(proposal.getPolicyId());
             } else {
                log.warn("연결된 Policy가 없습니다: proposalId={}", proposalId);
            }

        } catch (Exception e) {
            log.error("AI 정책 비활성화 실패: proposalId={}, error={}",
                    proposalId, e.getMessage(), e);
        }
    }

    
    @EventListener
    @Async
    @Transactional
    public void handlePolicyRolledBackEvent(PolicyActivationServiceImpl.PolicyChangeEvent event) {
        if (event.getChangeType() != PolicyActivationServiceImpl.PolicyChangeType.ROLLED_BACK) {
            return;
        }

        Long proposalId = event.getProposalId();
        
        try {
            PolicyEvolutionProposal proposal = proposalRepository.findById(proposalId)
                    .orElseThrow(() -> new IllegalArgumentException(
                            "PolicyEvolutionProposal을 찾을 수 없습니다: proposalId=" + proposalId));

            if (proposal.getPolicyId() != null) {
                
                policyService.deletePolicy(proposal.getPolicyId());
                
                
                proposal.setPolicyId(null);
                proposalRepository.save(proposal);
            } else {
                log.warn("롤백할 Policy가 없습니다: proposalId={}", proposalId);
            }

        } catch (Exception e) {
            log.error("AI 정책 롤백 실패: proposalId={}, error={}",
                    proposalId, e.getMessage(), e);
        }
    }

    
    private void reactivateExistingPolicy(PolicyEvolutionProposal proposal) {
        try {
            Policy existingPolicy = policyService.findById(proposal.getPolicyId());

            
            existingPolicy.setIsActive(true);
            existingPolicy.activate();

            
            reloadAuthorizationSystem();

            
        } catch (Exception e) {
            log.error("기존 정책 재활성화 실패: policyId={}, error={}",
                    proposal.getPolicyId(), e.getMessage(), e);
        }
    }

    
    private void updatePolicyForAIGenerated(Policy policy, PolicyEvolutionProposal proposal) {
        
        if (proposal.getParentProposalId() != null) {
            policy.setSource(Policy.PolicySource.AI_EVOLVED);
        } else {
            policy.setSource(Policy.PolicySource.AI_GENERATED);
        }

        
        policy.setApprovalStatus(Policy.ApprovalStatus.APPROVED);
        policy.setApprovedBy(proposal.getApprovedBy());
        policy.setApprovedAt(LocalDateTime.now());

        
        policy.setConfidenceScore(proposal.getConfidenceScore());

        
        Map<String, Object> metadata = proposal.getMetadata();
        if (metadata != null && metadata.containsKey("aiModel")) {
            policy.setAiModel(String.valueOf(metadata.get("aiModel")));
        }

        policy.setUpdatedAt(LocalDateTime.now());

            }

    
    private void linkProposalToPolicy(PolicyEvolutionProposal proposal, Policy policy) {
        proposal.setPolicyId(policy.getId());
        proposal.addMetadata("linked_policy_name", policy.getName());
        proposal.addMetadata("linked_at", LocalDateTime.now().toString());
        proposalRepository.save(proposal);

            }

    
    private void deactivatePolicy(Long policyId) {
        try {
            Policy policy = policyService.findById(policyId);
            policy.setIsActive(false);
            policy.deactivate();

            
            reloadAuthorizationSystem();

        } catch (Exception e) {
            log.error("정책 비활성화 중 오류: policyId={}", policyId, e);
        }
    }

    
    private void reloadAuthorizationSystem() {
        try {
            policyRetrievalPoint.clearUrlPoliciesCache();
            policyRetrievalPoint.clearMethodPoliciesCache();
            authorizationManager.reload();
        } catch (Exception e) {
            log.error("인가 시스템 재로드 실패", e);
        }
    }
}
