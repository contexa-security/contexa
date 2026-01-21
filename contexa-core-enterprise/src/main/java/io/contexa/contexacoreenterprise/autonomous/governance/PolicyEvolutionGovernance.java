package io.contexa.contexacoreenterprise.autonomous.governance;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalStatus;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import io.contexa.contexacore.autonomous.PolicyActivationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@RequiredArgsConstructor
public class PolicyEvolutionGovernance {
    
    private final PolicyProposalRepository proposalRepository;
    private final PolicyActivationService activationService;
    private final PolicyApprovalService approvalService;
    private final ApplicationEventPublisher eventPublisher;

    private final Map<String, GovernanceRule> governanceRules = new ConcurrentHashMap<>();

    @Value("${governance.auto-approve.enabled:false}")
    private boolean autoApproveEnabled;
    
    @Value("${governance.auto-approve.max-risk:LOW}")
    private String autoApproveMaxRisk;
    
    @Value("${governance.auto-approve.min-confidence:0.9}")
    private double autoApproveMinConfidence;
    
    @Value("${governance.multi-approval.threshold:MEDIUM}")
    private String multiApprovalThreshold;
    
    @Value("${governance.critical.min-approvers:3}")
    private int criticalMinApprovers;

    @Transactional
    public GovernanceDecision evaluateProposal(Long proposalId) {
                
        try {
            
            PolicyEvolutionProposal proposal = proposalRepository.findById(proposalId)
                .orElseThrow(() -> new IllegalArgumentException("Proposal not found: " + proposalId));

            if (!canEvaluate(proposal)) {
                return GovernanceDecision.builder()
                    .proposalId(proposalId)
                    .decision(DecisionType.SKIP)
                    .reason("Proposal cannot be evaluated in current state: " + proposal.getStatus())
                    .build();
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

    private RiskAssessment reassessRisk(PolicyEvolutionProposal proposal) {
                
        RiskAssessment assessment = new RiskAssessment();

        PolicyEvolutionProposal.RiskLevel baseRisk = proposal.getRiskLevel();
        assessment.setBaseRisk(baseRisk);

        double riskScore = 0.0;

        switch (proposal.getProposalType()) {
            case DELETE_POLICY:
            case REVOKE_ACCESS:
                riskScore += 0.3; 
                break;
            case CREATE_POLICY:
            case GRANT_ACCESS:
                riskScore += 0.2; 
                break;
            case UPDATE_POLICY:
            case OPTIMIZE_RULE:
                riskScore += 0.1; 
                break;
            default:
                riskScore += 0.05;
        }

        Double confidence = proposal.getConfidenceScore();
        if (confidence != null) {
            if (confidence < 0.5) {
                riskScore += 0.3; 
            } else if (confidence < 0.7) {
                riskScore += 0.1;
            } else if (confidence > 0.9) {
                riskScore -= 0.1; 
            }
        }

        Double expectedImpact = proposal.getExpectedImpact();
        if (expectedImpact != null && expectedImpact > 0.8) {
            riskScore += 0.2; 
        }

        if (proposal.getLearningType() != null) {
            switch (proposal.getLearningType()) {
                case THREAT_RESPONSE:
                    riskScore += 0.1; 
                    break;
                case ACCESS_PATTERN:
                    riskScore += 0.05;
                    break;
                case POLICY_FEEDBACK:
                    
                    break;
            }
        }

        riskScore = Math.max(0.0, Math.min(riskScore, 1.0));
        assessment.setRiskScore(riskScore);
        assessment.setAdjustedRisk(calculateAdjustedRisk(baseRisk, riskScore));
        assessment.setAssessmentTime(LocalDateTime.now());

        Map<String, Object> factors = new HashMap<>();
        factors.put("proposalType", proposal.getProposalType());
        factors.put("confidence", confidence);
        factors.put("expectedImpact", expectedImpact);
        factors.put("learningType", proposal.getLearningType());
        assessment.setRiskFactors(factors);
        
                return assessment;
    }

    private GovernanceDecision applyGovernanceRules(
            PolicyEvolutionProposal proposal, 
            RiskAssessment riskAssessment) {

        PolicyEvolutionProposal.RiskLevel adjustedRisk = riskAssessment.getAdjustedRisk();

        if (canAutoApprove(proposal, riskAssessment)) {
                        return GovernanceDecision.builder()
                .proposalId(proposal.getId())
                .decision(DecisionType.AUTO_APPROVE)
                .riskAssessment(riskAssessment)
                .reason("Low risk with high confidence")
                .autoApproved(true)
                .build();
        }

        if (needsMultiApproval(adjustedRisk)) {
            int requiredApprovers = calculateRequiredApprovers(adjustedRisk);
                        
            return GovernanceDecision.builder()
                .proposalId(proposal.getId())
                .decision(DecisionType.MULTI_APPROVAL_REQUIRED)
                .riskAssessment(riskAssessment)
                .requiredApprovers(requiredApprovers)
                .reason(String.format("%s risk requires %d approvers", adjustedRisk, requiredApprovers))
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
        if (!autoApproveEnabled) {
            return false;
        }

        PolicyEvolutionProposal.RiskLevel maxRisk = PolicyEvolutionProposal.RiskLevel.valueOf(autoApproveMaxRisk);
        if (riskAssessment.getAdjustedRisk().ordinal() > maxRisk.ordinal()) {
            return false;
        }

        Double confidence = proposal.getConfidenceScore();
        if (confidence == null || confidence < autoApproveMinConfidence) {
            return false;
        }

        for (GovernanceRule rule : governanceRules.values()) {
            if (!rule.allows(proposal, riskAssessment)) {
                return false;
            }
        }
        
        return true;
    }

    private boolean needsMultiApproval(PolicyEvolutionProposal.RiskLevel riskLevel) {
        PolicyEvolutionProposal.RiskLevel threshold = 
            PolicyEvolutionProposal.RiskLevel.valueOf(multiApprovalThreshold);
        return riskLevel.ordinal() >= threshold.ordinal();
    }

    private int calculateRequiredApprovers(PolicyEvolutionProposal.RiskLevel riskLevel) {
        switch (riskLevel) {
            case CRITICAL:
                return criticalMinApprovers;
            case HIGH:
                return 2;
            case MEDIUM:
                return 1;
            default:
                return 1;
        }
    }

    private PolicyEvolutionProposal.RiskLevel calculateAdjustedRisk(
            PolicyEvolutionProposal.RiskLevel baseRisk, double riskScore) {
        
        int adjustedOrdinal = baseRisk.ordinal();
        
        if (riskScore > 0.5) {
            adjustedOrdinal = Math.min(adjustedOrdinal + 2, PolicyEvolutionProposal.RiskLevel.CRITICAL.ordinal());
        } else if (riskScore > 0.3) {
            adjustedOrdinal = Math.min(adjustedOrdinal + 1, PolicyEvolutionProposal.RiskLevel.CRITICAL.ordinal());
        } else if (riskScore < -0.1) {
            adjustedOrdinal = Math.max(adjustedOrdinal - 1, PolicyEvolutionProposal.RiskLevel.LOW.ordinal());
        }
        
        return PolicyEvolutionProposal.RiskLevel.values()[adjustedOrdinal];
    }

    private void executeDecision(PolicyEvolutionProposal proposal, GovernanceDecision decision) {
                
        try {
            switch (decision.getDecision()) {
                case AUTO_APPROVE:
                    
                    proposal.setStatus(ProposalStatus.APPROVED);
                    proposal.setApprovedBy("SYSTEM_AUTO");
                    proposal.setReviewedAt(LocalDateTime.now());
                    proposalRepository.save(proposal);

                    activationService.activatePolicy(proposal.getId(), "SYSTEM_AUTO");
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
                    log.warn("Unhandled decision type: {}", decision.getDecision());
            }
        } catch (Exception e) {
            log.error("Failed to execute decision for proposal: {}", proposal.getId(), e);
            throw new GovernanceException("Decision execution failed", e);
        }
    }

    private boolean canEvaluate(PolicyEvolutionProposal proposal) {
        ProposalStatus status = proposal.getStatus();
        return status == ProposalStatus.PENDING || status == ProposalStatus.APPROVED;
    }

    private void publishGovernanceEvent(PolicyEvolutionProposal proposal, GovernanceDecision decision) {
        GovernanceEvent event = GovernanceEvent.builder()
            .proposalId(proposal.getId())
            .decision(decision)
            .timestamp(LocalDateTime.now())
            .build();
        
        eventPublisher.publishEvent(event);
    }

    public void addGovernanceRule(String ruleId, GovernanceRule rule) {
                governanceRules.put(ruleId, rule);
    }

    public void removeGovernanceRule(String ruleId) {
                governanceRules.remove(ruleId);
    }

    @lombok.Data
    public static class RiskAssessment {
        private PolicyEvolutionProposal.RiskLevel baseRisk;
        private PolicyEvolutionProposal.RiskLevel adjustedRisk;
        private double riskScore;
        private Map<String, Object> riskFactors;
        private LocalDateTime assessmentTime;
    }

    @lombok.Builder
    @lombok.Data
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

    public interface GovernanceRule {
        boolean allows(PolicyEvolutionProposal proposal, RiskAssessment assessment);
        String getRuleDescription();
    }

    @lombok.Builder
    @lombok.Data
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