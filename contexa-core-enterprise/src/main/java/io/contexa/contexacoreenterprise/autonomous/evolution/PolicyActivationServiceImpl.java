package io.contexa.contexacoreenterprise.autonomous.evolution;

import io.contexa.contexacore.autonomous.PolicyActivationService;
import io.contexa.contexacore.autonomous.domain.ActivationResult;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalStatus;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import io.contexa.contexacoreenterprise.autonomous.validation.SpelValidationService;
import lombok.Builder;
import lombok.Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class PolicyActivationServiceImpl implements PolicyActivationService {

    private static final Logger logger = LoggerFactory.getLogger(PolicyActivationServiceImpl.class);

    @Autowired
    private PolicyProposalRepository proposalRepository;

    @Autowired
    private ApplicationEventPublisher eventPublisher;

    @Autowired(required = false)
    private SpelValidationService spelValidationService;

    private final Map<Long, ActivationTask> activationTasks = new ConcurrentHashMap<>();

    @Override
    @Transactional
    public ActivationResult activatePolicy(Long proposalId, String activatedBy) {
        try {
            PolicyEvolutionProposal proposal = proposalRepository.findById(proposalId)
                .orElseThrow(() -> new IllegalArgumentException("Proposal not found: " + proposalId));

            if (!canActivate(proposal)) {
                return ActivationResult.failure(proposalId, "Policy cannot be activated in current state");
            }

            ActivationTask task = createActivationTask(proposal, activatedBy);
            activationTasks.put(proposalId, task);

            return executeActivation(task);

        } catch (Exception e) {
            logger.error("Failed to activate policy: {}", proposalId, e);
            return ActivationResult.failure(proposalId, "Activation failed: " + e.getMessage());
        } finally {
            activationTasks.remove(proposalId);
        }
    }

    @Override
    @Transactional
    public boolean deactivatePolicy(Long proposalId, String deactivatedBy, String reason) {
        try {
            PolicyEvolutionProposal proposal = proposalRepository.findById(proposalId)
                .orElseThrow(() -> new IllegalArgumentException("Proposal not found"));

            if (proposal.getStatus() != ProposalStatus.ACTIVATED) {
                logger.error("Policy {} is not active", proposalId);
                return false;
            }

            proposal.setStatus(ProposalStatus.DEACTIVATED);
            proposal.setDeactivatedAt(LocalDateTime.now());
            proposal.addMetadata("deactivated_by", deactivatedBy);
            proposal.addMetadata("deactivation_reason", reason);

            proposalRepository.save(proposal);

            publishPolicyChangeEvent(proposal, PolicyChangeType.DEACTIVATED);

            return true;

        } catch (Exception e) {
            logger.error("Failed to deactivate policy: {}", proposalId, e);
            return false;
        }
    }

    private boolean canActivate(PolicyEvolutionProposal proposal) {
        // Only APPROVED proposals can be activated - PENDING bypasses governance
        return proposal.getStatus() == ProposalStatus.APPROVED;
    }

    private ActivationTask createActivationTask(PolicyEvolutionProposal proposal, String activatedBy) {
        return ActivationTask.builder()
            .proposalId(proposal.getId())
            .activatedBy(activatedBy)
            .startTime(LocalDateTime.now())
            .status(ActivationStatus.PREPARING)
            .build();
    }

    private ActivationResult executeActivation(ActivationTask task) {
        try {
            task.setStatus(ActivationStatus.PREPARING);
            prepareActivation(task);

            task.setStatus(ActivationStatus.VALIDATING);
            validateActivation(task);

            task.setStatus(ActivationStatus.APPLYING);
            applyActivation(task);

            task.setStatus(ActivationStatus.VERIFYING);
            verifyActivation(task);

            task.setStatus(ActivationStatus.ACTIVE);

            return ActivationResult.success(task.getProposalId(), null);

        } catch (Exception e) {
            task.setStatus(ActivationStatus.FAILED);

            return ActivationResult.failure(task.getProposalId(), e.getMessage());
        }
    }

    private void prepareActivation(ActivationTask task) throws Exception {
        PolicyEvolutionProposal proposal = proposalRepository.findById(task.getProposalId())
            .orElseThrow(() -> new ActivationException("Proposal not found during preparation"));

        validateResourceAvailability(proposal);
    }

    private void validateResourceAvailability(PolicyEvolutionProposal proposal) throws ActivationException {
        switch (proposal.getProposalType()) {
            case CREATE_POLICY:
            case UPDATE_POLICY:
                if (proposal.getSpelExpression() == null || proposal.getSpelExpression().isEmpty()) {
                    throw new ActivationException("SpEL expression is required for policy creation/update");
                }
                validateSpelExpression(proposal.getSpelExpression());
                break;

            case DELETE_POLICY:
            case REVOKE_ACCESS:
                break;

            case ADJUST_THRESHOLD:
            case OPTIMIZE_RULE:
                if (proposal.getMetadata() == null || proposal.getMetadata().isEmpty()) {
                    throw new ActivationException("Metadata is required for threshold adjustment");
                }
                break;

            default:
                break;
        }
    }

    private void validateSpelExpression(String spelExpression) throws ActivationException {
        if (spelValidationService == null) {
            logger.error("SpEL validation service not available - blocking activation for expression: {}", spelExpression);
            throw new ActivationException("SpEL validation service not available");
        }
        SpelValidationService.ValidationResult result = spelValidationService.validate(spelExpression);
        if (!result.valid()) {
            throw new ActivationException("SpEL validation failed: " + String.join(", ", result.errors()));
        }
    }

    private void validateActivation(ActivationTask task) throws Exception {
        proposalRepository.findById(task.getProposalId())
            .orElseThrow(() -> new IllegalStateException("Proposal not found"));
    }

    private void applyActivation(ActivationTask task) throws Exception {
        PolicyEvolutionProposal proposal = proposalRepository.findById(task.getProposalId())
            .orElseThrow(() -> new IllegalStateException("Proposal not found"));

        proposal.setStatus(ProposalStatus.ACTIVATED);
        proposal.setActivatedAt(LocalDateTime.now());
        proposal.setActivatedBy(task.getActivatedBy());
        proposalRepository.save(proposal);

        publishPolicyChangeEvent(proposal, PolicyChangeType.ACTIVATED);
    }

    private void verifyActivation(ActivationTask task) throws Exception {
        PolicyEvolutionProposal proposal = proposalRepository.findById(task.getProposalId())
            .orElseThrow(() -> new ActivationException("Proposal not found during verification"));

        if (proposal.getStatus() != ProposalStatus.ACTIVATED) {
            throw new ActivationException("Proposal status is not ACTIVATED: " + proposal.getStatus());
        }

        if (proposal.getActivatedAt() == null) {
            throw new ActivationException("Activation timestamp is missing");
        }

        if (proposal.getActivatedBy() == null || proposal.getActivatedBy().isEmpty()) {
            throw new ActivationException("Activator information is missing");
        }
    }

    private void publishPolicyChangeEvent(PolicyEvolutionProposal proposal, PolicyChangeType changeType) {
        PolicyChangeEvent event = PolicyChangeEvent.builder()
            .proposalId(proposal.getId())
            .changeType(changeType)
            .policyRules(extractPolicyRules(proposal))
            .timestamp(LocalDateTime.now())
            .build();

        eventPublisher.publishEvent(event);
    }

    private Map<String, Object> extractPolicyRules(PolicyEvolutionProposal proposal) {
        Map<String, Object> rules = new HashMap<>();

        rules.put("id", proposal.getId());
        rules.put("type", proposal.getProposalType());
        rules.put("content", proposal.getPolicyContent());
        rules.put("metadata", proposal.getMetadata());

        return rules;
    }

    @Builder
    @Data
    private static class ActivationTask {
        private Long proposalId;
        private String activatedBy;
        private LocalDateTime startTime;
        private ActivationStatus status;
    }

    public enum ActivationStatus {
        PREPARING,
        VALIDATING,
        APPLYING,
        VERIFYING,
        ACTIVE,
        DEACTIVATED,
        FAILED
    }

    @Builder
    @Data
    public static class PolicyChangeEvent {
        private Long proposalId;
        private PolicyChangeType changeType;
        private Map<String, Object> policyRules;
        private LocalDateTime timestamp;
    }

    public enum PolicyChangeType {
        ACTIVATED,
        DEACTIVATED
    }

    public static class ActivationException extends Exception {
        public ActivationException(String message) {
            super(message);
        }

        public ActivationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
