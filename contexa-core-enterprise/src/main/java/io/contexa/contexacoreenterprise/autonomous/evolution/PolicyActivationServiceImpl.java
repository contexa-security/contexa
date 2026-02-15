package io.contexa.contexacoreenterprise.autonomous.evolution;

import io.contexa.contexacore.autonomous.PolicyActivationService;
import io.contexa.contexacore.autonomous.domain.ActivationResult;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalStatus;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Async;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class PolicyActivationServiceImpl implements PolicyActivationService {

    private static final Logger logger = LoggerFactory.getLogger(PolicyActivationServiceImpl.class);

    @Autowired
    private PolicyProposalRepository proposalRepository;

    @Autowired
    private ApplicationEventPublisher eventPublisher;

    private final Map<Long, ActivationTask> activationTasks = new ConcurrentHashMap<>();

    private final ActivationMetrics metrics = new ActivationMetrics();

    @Override
    @Transactional
    public ActivationResult activatePolicy(Long proposalId, String activatedBy) {
        logger.info("Activating policy {} requested by {}", proposalId, activatedBy);

        try {
            PolicyEvolutionProposal proposal = proposalRepository.findById(proposalId)
                .orElseThrow(() -> new IllegalArgumentException("Proposal not found: " + proposalId));

            if (!canActivate(proposal)) {
                return ActivationResult.failure(proposalId, "Policy cannot be activated in current state");
            }

            ActivationTask task = createActivationTask(proposal, activatedBy);
            activationTasks.put(proposalId, task);

            CompletableFuture<ActivationResult> future = executeActivation(task);

            ActivationResult result = future.get(30, TimeUnit.SECONDS);

            updateMetrics(result);

            return result;

        } catch (Exception e) {
            logger.error("Failed to activate policy: {}", proposalId, e);
            return ActivationResult.failure(proposalId, "Activation failed: " + e.getMessage());
        }
    }

    @Override
    @Transactional
    public boolean deactivatePolicy(Long proposalId, String deactivatedBy, String reason) {
        logger.info("Deactivating policy {} requested by {}: {}", proposalId, deactivatedBy, reason);

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

            publishDeactivationEvent(proposal, deactivatedBy, reason);

            logger.info("Policy {} successfully deactivated", proposalId);
            return true;

        } catch (Exception e) {
            logger.error("Failed to deactivate policy: {}", proposalId, e);
            return false;
        }
    }

    @Async
    public CompletableFuture<List<ActivationResult>> batchActivate(
            List<Long> proposalIds, String activatedBy) {

        logger.info("Batch activating {} policies", proposalIds.size());

        List<CompletableFuture<ActivationResult>> futures = proposalIds.stream()
            .map(id -> CompletableFuture.supplyAsync(() -> activatePolicy(id, activatedBy)))
            .collect(Collectors.toList());

        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
            .thenApply(v -> futures.stream()
                .map(CompletableFuture::join)
                .collect(Collectors.toList()));
    }

    public ActivationResult conditionalActivate(Long proposalId, ActivationConditions conditions) {
        logger.info("Conditional activation for policy {} with conditions: {}", proposalId, conditions);

        try {
            PolicyEvolutionProposal proposal = proposalRepository.findById(proposalId)
                .orElseThrow(() -> new IllegalArgumentException("Proposal not found"));

            if (!validateConditions(proposal, conditions)) {
                return ActivationResult.failure(proposalId, "Activation conditions not met");
            }

            return activatePolicy(proposalId, conditions.getRequestedBy());

        } catch (Exception e) {
            logger.error("Conditional activation failed: {}", proposalId, e);
            return ActivationResult.failure(proposalId, e.getMessage());
        }
    }

    public ActivationStatus getActivationStatus(Long proposalId) {
        ActivationTask task = activationTasks.get(proposalId);

        if (task == null) {
            PolicyEvolutionProposal proposal = proposalRepository.findById(proposalId).orElse(null);
            if (proposal == null) {
                return ActivationStatus.NOT_FOUND;
            }

            return mapStatusToActivationStatus(proposal.getStatus());
        }

        return task.getStatus();
    }

    @Transactional
    public boolean rollbackActivation(Long proposalId, String reason) {
        logger.error("Rolling back activation for policy {}: {}", proposalId, reason);

        try {
            PolicyEvolutionProposal proposal = proposalRepository.findById(proposalId)
                .orElseThrow(() -> new IllegalArgumentException("Proposal not found"));

            proposal.setStatus(ProposalStatus.ROLLED_BACK);
            proposal.addMetadata("rollback_reason", reason);
            proposal.addMetadata("rollback_time", LocalDateTime.now().toString());

            proposalRepository.save(proposal);

            publishPolicyChangeEvent(proposal, PolicyChangeType.ROLLED_BACK);

            logger.info("Successfully rolled back policy {}", proposalId);
            return true;

        } catch (Exception e) {
            logger.error("Failed to rollback policy: {}", proposalId, e);
            return false;
        }
    }

    public ActivationMetrics getMetrics() {
        return metrics.snapshot();
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

    @Async
    public CompletableFuture<ActivationResult> executeActivation(ActivationTask task) {
        return CompletableFuture.supplyAsync(() -> {
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
                task.setEndTime(LocalDateTime.now());

                return ActivationResult.success(task.getProposalId(), null);

            } catch (Exception e) {
                task.setStatus(ActivationStatus.FAILED);
                task.setError(e.getMessage());

                return ActivationResult.failure(task.getProposalId(), e.getMessage());
            }
        });
    }

    private void prepareActivation(ActivationTask task) throws Exception {
        logger.debug("Preparing activation for proposal {}", task.getProposalId());

        PolicyEvolutionProposal proposal = proposalRepository.findById(task.getProposalId())
            .orElseThrow(() -> new ActivationException("Proposal not found during preparation"));

        validateResourceAvailability(proposal);

        logger.info("Activation preparation completed for proposal {}", task.getProposalId());
    }

    private void validateResourceAvailability(PolicyEvolutionProposal proposal) throws ActivationException {
        switch (proposal.getProposalType()) {
            case CREATE_POLICY:
            case UPDATE_POLICY:
                if (proposal.getSpelExpression() == null || proposal.getSpelExpression().isEmpty()) {
                    throw new ActivationException("SpEL expression is required for policy creation/update");
                }
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
                logger.debug("No specific resource validation for type: {}", proposal.getProposalType());
        }
    }

    private void validateActivation(ActivationTask task) throws Exception {
        logger.debug("Validating activation for proposal {}", task.getProposalId());

        proposalRepository.findById(task.getProposalId())
            .orElseThrow(() -> new IllegalStateException("Proposal not found"));
    }

    private void applyActivation(ActivationTask task) throws Exception {
        logger.info("Applying activation for proposal {}", task.getProposalId());

        PolicyEvolutionProposal proposal = proposalRepository.findById(task.getProposalId())
            .orElseThrow(() -> new IllegalStateException("Proposal not found"));

        publishPolicyChangeEvent(proposal, PolicyChangeType.ACTIVATED);

        proposal.setStatus(ProposalStatus.ACTIVATED);
        proposal.setActivatedAt(LocalDateTime.now());
        proposal.setActivatedBy(task.getActivatedBy());

        proposalRepository.save(proposal);

        publishActivationEvent(proposal, task);
    }

    private void verifyActivation(ActivationTask task) throws Exception {
        logger.debug("Verifying activation for proposal {}", task.getProposalId());

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

        logger.info("Activation verification completed for proposal {}", task.getProposalId());
    }

    private void publishPolicyChangeEvent(PolicyEvolutionProposal proposal, PolicyChangeType changeType) {
        logger.info("Publishing policy change event: {} for policy {}", changeType, proposal.getId());

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

    private boolean validateConditions(PolicyEvolutionProposal proposal,
                                      ActivationConditions conditions) {
        if (conditions.getActivateAfter() != null &&
            LocalDateTime.now().isBefore(conditions.getActivateAfter())) {
            return false;
        }

        if (conditions.getMaxRiskLevel() != null &&
            proposal.getRiskLevel().ordinal() > conditions.getMaxRiskLevel().ordinal()) {
            return false;
        }

        if (conditions.getMinConfidenceScore() != null &&
            proposal.getConfidenceScore() < conditions.getMinConfidenceScore()) {
            return false;
        }

        return true;
    }

    private void updateMetrics(ActivationResult result) {
        if (result.isSuccess()) {
            metrics.incrementSuccessCount();
        } else {
            metrics.incrementFailureCount();
        }

        metrics.updateLastActivation(LocalDateTime.now());
    }

    private ActivationStatus mapStatusToActivationStatus(ProposalStatus status) {
        switch (status) {
            case ACTIVATED:
                return ActivationStatus.ACTIVE;
            case DEACTIVATED:
                return ActivationStatus.DEACTIVATED;
            case ROLLED_BACK:
                return ActivationStatus.ROLLED_BACK;
            default:
                return ActivationStatus.INACTIVE;
        }
    }

    private void publishActivationEvent(PolicyEvolutionProposal proposal, ActivationTask task) {
        ActivationEvent event = ActivationEvent.builder()
            .proposalId(proposal.getId())
            .activatedBy(task.getActivatedBy())
            .timestamp(LocalDateTime.now())
            .build();

        eventPublisher.publishEvent(event);
    }

    private void publishDeactivationEvent(PolicyEvolutionProposal proposal,
                                         String deactivatedBy, String reason) {
        DeactivationEvent event = DeactivationEvent.builder()
            .proposalId(proposal.getId())
            .deactivatedBy(deactivatedBy)
            .reason(reason)
            .timestamp(LocalDateTime.now())
            .build();

        eventPublisher.publishEvent(event);
    }

    @lombok.Builder
    @lombok.Data
    private static class ActivationTask {
        private Long proposalId;
        private String activatedBy;
        private LocalDateTime startTime;
        private LocalDateTime endTime;
        private ActivationStatus status;
        private String error;
    }

    @lombok.Builder
    @lombok.Data
    public static class ActivationConditions {
        private String requestedBy;
        private LocalDateTime activateAfter;
        private PolicyEvolutionProposal.RiskLevel maxRiskLevel;
        private Double minConfidenceScore;
        private Map<String, Object> customConditions;
    }

    @lombok.Data
    public static class ActivationMetrics {
        private long totalActivations = 0;
        private long successfulActivations = 0;
        private long failedActivations = 0;
        private LocalDateTime lastActivation;

        public void incrementSuccessCount() {
            totalActivations++;
            successfulActivations++;
        }

        public void incrementFailureCount() {
            totalActivations++;
            failedActivations++;
        }

        public void updateLastActivation(LocalDateTime time) {
            lastActivation = time;
        }

        public double getSuccessRate() {
            if (totalActivations == 0) return 0.0;
            return (double) successfulActivations / totalActivations;
        }

        public ActivationMetrics snapshot() {
            ActivationMetrics snapshot = new ActivationMetrics();
            snapshot.totalActivations = this.totalActivations;
            snapshot.successfulActivations = this.successfulActivations;
            snapshot.failedActivations = this.failedActivations;
            snapshot.lastActivation = this.lastActivation;
            return snapshot;
        }
    }

    @lombok.Builder
    @lombok.Data
    public static class ActivationEvent {
        private Long proposalId;
        private String activatedBy;
        private LocalDateTime timestamp;
    }

    @lombok.Builder
    @lombok.Data
    public static class DeactivationEvent {
        private Long proposalId;
        private String deactivatedBy;
        private String reason;
        private LocalDateTime timestamp;
    }

    public enum ActivationStatus {
        PREPARING,
        VALIDATING,
        APPLYING,
        VERIFYING,
        ACTIVE,
        INACTIVE,
        DEACTIVATED,
        FAILED,
        ROLLED_BACK,
        NOT_FOUND
    }

    @lombok.Builder
    @lombok.Data
    public static class PolicyChangeEvent {
        private Long proposalId;
        private PolicyChangeType changeType;
        private Map<String, Object> policyRules;
        private LocalDateTime timestamp;
    }

    public enum PolicyChangeType {
        ACTIVATED,
        DEACTIVATED,
        ROLLED_BACK
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
