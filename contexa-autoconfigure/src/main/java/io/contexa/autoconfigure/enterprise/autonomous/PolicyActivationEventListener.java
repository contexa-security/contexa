package io.contexa.autoconfigure.enterprise.autonomous;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import io.contexa.contexacoreenterprise.autonomous.evolution.PolicyActivationServiceImpl;
import io.contexa.contexacoreenterprise.repository.SynthesisPolicyRepository;
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
    private final SynthesisPolicyRepository synthesisPolicyRepository;

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
                            "PolicyEvolutionProposal not found: proposalId=" + proposalId));

            if (proposal.getPolicyId() != null) {

                reactivateExistingPolicy(proposal);
                return;
            }

            PolicyDto policyDto = proposalToPolicyConverter.convert(proposal);

            Policy savedPolicy = policyService.createPolicy(policyDto);

            updatePolicyForAIGenerated(savedPolicy, proposal);

            linkProposalToPolicy(proposal, savedPolicy);

            cachePolicyForWorkbench(savedPolicy, proposal);

            reloadAuthorizationSystem();

        } catch (Exception e) {
            log.error("AI policy activation failed: proposalId={}, error={}",
                    proposalId, e.getMessage(), e);

            rollbackProposalStatus(proposalId);
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
                            "PolicyEvolutionProposal not found: proposalId=" + proposalId));

            if (proposal.getPolicyId() != null) {

                deactivatePolicy(proposal.getPolicyId());
            } else {
                log.error("No linked Policy found: proposalId={}", proposalId);
            }

        } catch (Exception e) {
            log.error("AI policy deactivation failed: proposalId={}, error={}",
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
            log.error("Existing policy reactivation failed: policyId={}, error={}",
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
            log.error("Error deactivating policy: policyId={}", policyId, e);
        }
    }

    private void cachePolicyForWorkbench(Policy savedPolicy, PolicyEvolutionProposal proposal) {
        try {
            SynthesisPolicyRepository.Policy cachePolicy = SynthesisPolicyRepository.Policy.builder()
                    .policyId(savedPolicy.getId())
                    .proposalId(proposal.getId())
                    .policyName(savedPolicy.getName())
                    .policyType(proposal.getProposalType() != null ? proposal.getProposalType().name() : "UNKNOWN")
                    .spelExpression(proposal.getSpelExpression())
                    .status(SynthesisPolicyRepository.PolicyStatus.ACTIVE)
                    .createdBy(proposal.getApprovedBy())
                    .build();
            synthesisPolicyRepository.save(cachePolicy);
        } catch (Exception e) {
            log.error("Failed to cache policy for workbench: policyId={}", savedPolicy.getId(), e);
        }
    }

    private void rollbackProposalStatus(Long proposalId) {
        try {
            proposalRepository.findById(proposalId).ifPresent(p -> {
                p.setStatus(PolicyEvolutionProposal.ProposalStatus.ROLLED_BACK);
                proposalRepository.save(p);
            });
        } catch (Exception rollbackEx) {
            log.error("Failed to rollback proposal status: proposalId={}", proposalId, rollbackEx);
        }
    }

    private static final int MAX_RELOAD_RETRIES = 3;

    private void reloadAuthorizationSystem() {
        Exception lastException = null;
        for (int attempt = 1; attempt <= MAX_RELOAD_RETRIES; attempt++) {
            try {
                policyRetrievalPoint.clearUrlPoliciesCache();
                policyRetrievalPoint.clearMethodPoliciesCache();
                authorizationManager.reload();
                return;
            } catch (Exception e) {
                lastException = e;
                log.error("Authorization system reload failed (attempt {}/{}): {}",
                        attempt, MAX_RELOAD_RETRIES, e.getMessage());
                if (attempt < MAX_RELOAD_RETRIES) {
                    try {
                        Thread.sleep(500L * attempt);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
        }
        throw new RuntimeException("Authorization system reload failed after " +
                MAX_RELOAD_RETRIES + " retries", lastException);
    }
}
