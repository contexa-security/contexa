package io.contexa.contexacoreenterprise.autonomous.governance;

import io.contexa.contexacore.domain.entity.ProposalImpactLevel;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalStatus;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import io.contexa.contexacore.autonomous.PolicyActivationService;
import io.contexa.contexacoreenterprise.properties.GovernanceProperties;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

@Slf4j
@RequiredArgsConstructor
public class PolicyEvolutionGovernance {

    private static final String SYSTEM_AUTO_ACTOR = "SYSTEM_AUTO";

    private final PolicyProposalRepository proposalRepository;
    private final PolicyActivationService activationService;
    private final PolicyApprovalService approvalService;
    private final ApplicationEventPublisher eventPublisher;
    private final GovernanceProperties governanceProperties;

    @Transactional
    public GovernanceDecision evaluateProposal(Long proposalId) {
                
        try {
            
            PolicyEvolutionProposal proposal = proposalRepository.findById(proposalId)
                .orElseThrow(() -> new IllegalArgumentException("Proposal not found: " + proposalId));

            if (!canEvaluate(proposal)) {
                GovernanceDecision skipDecision = GovernanceDecision.builder()
                    .proposalId(proposalId)
                    .decision(DecisionType.SKIP)
                    .reason("Proposal cannot be evaluated in current state: " + proposal.getStatus())
                    .build();
                publishGovernanceEvent(proposal, skipDecision);
                return skipDecision;
            }

            RiskAssessment riskAssessment = reassessRisk(proposal);

            GovernanceDecision decision = applyGovernanceRules(proposal, riskAssessment);

            executeDecision(proposal, decision);

            publishGovernanceEvent(proposal, decision);
            
                        return decision;
            
        } catch (Exception e) {
            log.error("Failed to evaluate proposal: {}", proposalId, e);
            return GovernanceDecision.builder()
                .proposalId(proposalId)
                .decision(DecisionType.ERROR)
                .reason("Evaluation failed: " + e.getMessage())
                .build();
        }
    }

    // Reassesses proposal impact by aggregating weighted factors (type, impact, learning)
    // into a [0.0, 1.0] score, then shifting the base impact level up or down by 0/1/2 levels.
    // Confidence-based impact adjustment is handled in PolicyEvolutionEngine only (no double-counting).
    // All weights are externalized in GovernanceProperties for operational tuning.
    private RiskAssessment reassessRisk(PolicyEvolutionProposal proposal) {
        RiskAssessment assessment = new RiskAssessment();
        GovernanceProperties.ImpactWeightSettings weights = governanceProperties.getImpactWeights();

        ProposalImpactLevel baseImpact = proposal.getImpactLevel();
        assessment.setBaseImpact(baseImpact);

        double impactScore = 0.0;

        switch (proposal.getProposalType()) {
            case DELETE_POLICY:
            case REVOKE_ACCESS:
                impactScore += weights.getDeletePolicyWeight();
                break;
            case CREATE_POLICY:
            case GRANT_ACCESS:
                impactScore += weights.getCreatePolicyWeight();
                break;
            case UPDATE_POLICY:
            case OPTIMIZE_RULE:
                impactScore += weights.getUpdatePolicyWeight();
                break;
            default:
                impactScore += weights.getDefaultTypeWeight();
        }

        Double expectedImpact = proposal.getExpectedImpact();
        if (expectedImpact != null && expectedImpact > weights.getHighImpactThreshold()) {
            impactScore += weights.getHighImpactWeight();
        }

        if (proposal.getLearningType() != null) {
            switch (proposal.getLearningType()) {
                case THREAT_RESPONSE:
                    impactScore += weights.getThreatResponseWeight();
                    break;
                case ACCESS_PATTERN:
                    impactScore += weights.getAccessPatternWeight();
                    break;
                case POLICY_FEEDBACK:
                    break;
            }
        }

        impactScore = Math.max(0.0, Math.min(impactScore, 1.0));
        assessment.setImpactScore(impactScore);
        assessment.setAdjustedImpact(calculateAdjustedImpact(baseImpact, impactScore, weights));
        assessment.setAssessmentTime(LocalDateTime.now());

        Map<String, Object> factors = new HashMap<>();
        factors.put("proposalType", proposal.getProposalType());
        factors.put("expectedImpact", expectedImpact);
        factors.put("learningType", proposal.getLearningType());
        assessment.setImpactFactors(factors);

        return assessment;
    }

    private GovernanceDecision applyGovernanceRules(
            PolicyEvolutionProposal proposal, 
            RiskAssessment riskAssessment) {

        ProposalImpactLevel adjustedImpact = riskAssessment.getAdjustedImpact();

        // Reject proposals that do not meet minimum quality requirements
        GovernanceProperties.RejectionSettings rejectionSettings = governanceProperties.getRejection();

        if (proposal.getSpelExpression() == null || proposal.getSpelExpression().isBlank()) {
            return GovernanceDecision.builder()
                .proposalId(proposal.getId())
                .decision(DecisionType.REJECT)
                .riskAssessment(riskAssessment)
                .reason("SpEL expression is null or blank")
                .build();
        }

        Double confidence = proposal.getConfidenceScore();
        double conf = confidence != null ? confidence : 0.0;
        if (conf < rejectionSettings.getAbsoluteMinConfidence()) {
            return GovernanceDecision.builder()
                .proposalId(proposal.getId())
                .decision(DecisionType.REJECT)
                .riskAssessment(riskAssessment)
                .reason(String.format("Confidence %.2f below absolute minimum %.2f",
                    conf, rejectionSettings.getAbsoluteMinConfidence()))
                .build();
        }

        if (adjustedImpact == ProposalImpactLevel.CRITICAL && conf < rejectionSettings.getCriticalMinConfidence()) {
            return GovernanceDecision.builder()
                .proposalId(proposal.getId())
                .decision(DecisionType.REJECT)
                .riskAssessment(riskAssessment)
                .reason(String.format("CRITICAL impact with confidence %.2f below minimum %.2f",
                    conf, rejectionSettings.getCriticalMinConfidence()))
                .build();
        }

        if (canAutoApprove(proposal, riskAssessment)) {
                        return GovernanceDecision.builder()
                .proposalId(proposal.getId())
                .decision(DecisionType.AUTO_APPROVE)
                .riskAssessment(riskAssessment)
                .reason("Low risk with high confidence")
                .autoApproved(true)
                .build();
        }

        if (needsMultiApproval(adjustedImpact)) {
            int requiredApprovers = calculateRequiredApprovers(adjustedImpact);
                        
            return GovernanceDecision.builder()
                .proposalId(proposal.getId())
                .decision(DecisionType.MULTI_APPROVAL_REQUIRED)
                .riskAssessment(riskAssessment)
                .requiredApprovers(requiredApprovers)
                .reason(String.format("%s impact requires %d approvers", adjustedImpact, requiredApprovers))
                .build();
        }

                return GovernanceDecision.builder()
            .proposalId(proposal.getId())
            .decision(DecisionType.SINGLE_APPROVAL_REQUIRED)
            .riskAssessment(riskAssessment)
            .requiredApprovers(1)
            .reason("Standard approval process")
            .build();
    }

    private boolean canAutoApprove(PolicyEvolutionProposal proposal, RiskAssessment riskAssessment) {
        if (!governanceProperties.getAutoApprove().isEnabled()) {
            return false;
        }

        ProposalImpactLevel maxImpact;
        try {
            maxImpact = ProposalImpactLevel.valueOf(governanceProperties.getAutoApprove().getMaxImpact());
        } catch (IllegalArgumentException e) {
            log.error("Invalid auto-approve maxImpact configuration: {}", governanceProperties.getAutoApprove().getMaxImpact(), e);
            return false;
        }
        if (riskAssessment.getAdjustedImpact().ordinal() > maxImpact.ordinal()) {
            return false;
        }

        Double confidence = proposal.getConfidenceScore();
        if (confidence == null || confidence < governanceProperties.getAutoApprove().getMinConfidence()) {
            return false;
        }

        return true;
    }

    private boolean needsMultiApproval(ProposalImpactLevel impactLevel) {
        ProposalImpactLevel threshold;
        try {
            threshold = ProposalImpactLevel.valueOf(governanceProperties.getMultiApproval().getThreshold());
        } catch (IllegalArgumentException e) {
            log.error("Invalid multi-approval threshold configuration: {}", governanceProperties.getMultiApproval().getThreshold(), e);
            return true;
        }
        return impactLevel.ordinal() >= threshold.ordinal();
    }

    private int calculateRequiredApprovers(ProposalImpactLevel impactLevel) {
        GovernanceProperties.ApproverCountSettings approvers = governanceProperties.getApproverCount();
        switch (impactLevel) {
            case CRITICAL:
                return approvers.getCriticalApprovers();
            case HIGH:
                return approvers.getHighApprovers();
            case MEDIUM:
                return approvers.getMediumApprovers();
            default:
                return approvers.getDefaultApprovers();
        }
    }

    private ProposalImpactLevel calculateAdjustedImpact(
            ProposalImpactLevel baseImpact, double impactScore,
            GovernanceProperties.ImpactWeightSettings weights) {

        int adjustedOrdinal = baseImpact.ordinal();

        if (impactScore > weights.getMajorUpThreshold()) {
            adjustedOrdinal = Math.min(adjustedOrdinal + 2, ProposalImpactLevel.CRITICAL.ordinal());
        } else if (impactScore > weights.getMinorUpThreshold()) {
            adjustedOrdinal = Math.min(adjustedOrdinal + 1, ProposalImpactLevel.CRITICAL.ordinal());
        } else if (impactScore < weights.getMajorDownThreshold()) {
            adjustedOrdinal = Math.max(adjustedOrdinal - 2, ProposalImpactLevel.LOW.ordinal());
        } else if (impactScore < weights.getMinorDownThreshold()) {
            adjustedOrdinal = Math.max(adjustedOrdinal - 1, ProposalImpactLevel.LOW.ordinal());
        }

        return ProposalImpactLevel.values()[adjustedOrdinal];
    }

    private void executeDecision(PolicyEvolutionProposal proposal, GovernanceDecision decision) {
                
        try {
            switch (decision.getDecision()) {
                case AUTO_APPROVE:
                    
                    proposal.setStatus(ProposalStatus.APPROVED);
                    proposal.setApprovedBy(SYSTEM_AUTO_ACTOR);
                    proposal.setReviewedAt(LocalDateTime.now());
                    proposalRepository.save(proposal);

                    activationService.activatePolicy(proposal.getId(), SYSTEM_AUTO_ACTOR);
                    break;
                    
                case MULTI_APPROVAL_REQUIRED:
                    
                    approvalService.initiateMultiApproval(
                        proposal.getId(), 
                        decision.getRequiredApprovers(),
                        decision.getRiskAssessment()
                    );
                    break;
                    
                case SINGLE_APPROVAL_REQUIRED:
                    
                    approvalService.initiateSingleApproval(
                        proposal.getId(),
                        decision.getRiskAssessment()
                    );
                    break;
                    
                case REJECT:
                    
                    proposal.setStatus(ProposalStatus.REJECTED);
                    proposal.setRejectionReason(decision.getReason());
                    proposal.setReviewedAt(LocalDateTime.now());
                    proposalRepository.save(proposal);
                    break;
                    
                default:
                    throw new GovernanceException("Unhandled decision type: " + decision.getDecision());
            }
        } catch (Exception e) {
            log.error("Failed to execute decision for proposal: {}", proposal.getId(), e);
            throw new GovernanceException("Decision execution failed", e);
        }
    }

    private boolean canEvaluate(PolicyEvolutionProposal proposal) {
        ProposalStatus status = proposal.getStatus();
        return status == ProposalStatus.PENDING;
    }

    private void publishGovernanceEvent(PolicyEvolutionProposal proposal, GovernanceDecision decision) {
        GovernanceEvent event = GovernanceEvent.builder()
            .proposalId(proposal.getId())
            .decision(decision)
            .timestamp(LocalDateTime.now())
            .build();
        
        eventPublisher.publishEvent(event);
    }

    @Data
    public static class RiskAssessment implements java.io.Serializable {
        private static final long serialVersionUID = 1L;
        private ProposalImpactLevel baseImpact;
        private ProposalImpactLevel adjustedImpact;
        private double impactScore;
        private Map<String, Object> impactFactors;
        private LocalDateTime assessmentTime;
    }

    @Builder
    @Data
    public static class GovernanceDecision {
        private Long proposalId;
        private DecisionType decision;
        private RiskAssessment riskAssessment;
        private String reason;
        private int requiredApprovers;
        private boolean autoApproved;
    }

    public enum DecisionType {
        AUTO_APPROVE,
        SINGLE_APPROVAL_REQUIRED,
        MULTI_APPROVAL_REQUIRED,
        REJECT,
        SKIP,
        ERROR
    }

    @Builder
    @Data
    public static class GovernanceEvent {
        private Long proposalId;
        private GovernanceDecision decision;
        private LocalDateTime timestamp;
    }

    public static class GovernanceException extends RuntimeException {
        public GovernanceException(String message) {
            super(message);
        }
        
        public GovernanceException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}