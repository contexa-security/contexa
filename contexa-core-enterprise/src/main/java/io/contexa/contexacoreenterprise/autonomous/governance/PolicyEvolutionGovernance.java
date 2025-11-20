package io.contexa.contexacoreenterprise.autonomous.governance;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalStatus;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import io.contexa.contexacore.autonomous.PolicyActivationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 정책 진화 거버넌스
 *
 * 정책 제안의 위험도를 재평가하고 승인 프로세스를 관리합니다.
 * 자동 승인, 다단계 승인, 거부 등의 거버넌스 규칙을 적용합니다.
 *
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@ConditionalOnClass(name = "io.contexa.contexacore.repository.PolicyProposalRepository")
@Service
@RequiredArgsConstructor
public class PolicyEvolutionGovernance {
    
    private final PolicyProposalRepository proposalRepository;
    private final PolicyActivationService activationService;
    private final PolicyApprovalService approvalService;
    private final ApplicationEventPublisher eventPublisher;
    
    // 거버넌스 규칙 저장소
    private final Map<String, GovernanceRule> governanceRules = new ConcurrentHashMap<>();
    
    // 설정값
    @Value("${governance.auto-approve.enabled:true}")
    private boolean autoApproveEnabled;
    
    @Value("${governance.auto-approve.max-risk:LOW}")
    private String autoApproveMaxRisk;
    
    @Value("${governance.auto-approve.min-confidence:0.9}")
    private double autoApproveMinConfidence;
    
    @Value("${governance.multi-approval.threshold:MEDIUM}")
    private String multiApprovalThreshold;
    
    @Value("${governance.critical.min-approvers:3}")
    private int criticalMinApprovers;
    
    /**
     * 제안 평가 및 라우팅
     * 
     * @param proposalId 제안 ID
     * @return 거버넌스 결정
     */
    @Transactional
    public GovernanceDecision evaluateProposal(Long proposalId) {
        log.info("Evaluating proposal {} for governance decision", proposalId);
        
        try {
            // 1. 제안 조회
            PolicyEvolutionProposal proposal = proposalRepository.findById(proposalId)
                .orElseThrow(() -> new IllegalArgumentException("Proposal not found: " + proposalId));
            
            // 2. 상태 검증
            if (!canEvaluate(proposal)) {
                return GovernanceDecision.builder()
                    .proposalId(proposalId)
                    .decision(DecisionType.SKIP)
                    .reason("Proposal cannot be evaluated in current state: " + proposal.getStatus())
                    .build();
            }
            
            // 3. 위험도 재평가
            RiskAssessment riskAssessment = reassessRisk(proposal);
            
            // 4. 거버넌스 규칙 적용
            GovernanceDecision decision = applyGovernanceRules(proposal, riskAssessment);
            
            // 5. 결정 실행
            executeDecision(proposal, decision);
            
            // 6. 이벤트 발행
            publishGovernanceEvent(proposal, decision);
            
            log.info("Governance decision for proposal {}: {}", proposalId, decision.getDecision());
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
    
    /**
     * 위험도 재평가
     * 
     * @param proposal 제안
     * @return 위험 평가 결과
     */
    private RiskAssessment reassessRisk(PolicyEvolutionProposal proposal) {
        log.debug("Reassessing risk for proposal: {}", proposal.getId());
        
        RiskAssessment assessment = new RiskAssessment();
        
        // 기본 위험도
        PolicyEvolutionProposal.RiskLevel baseRisk = proposal.getRiskLevel();
        assessment.setBaseRisk(baseRisk);
        
        // 위험 요소 평가
        double riskScore = 0.0;
        
        // 1. 제안 유형에 따른 위험도
        switch (proposal.getProposalType()) {
            case DELETE_POLICY:
            case REVOKE_ACCESS:
                riskScore += 0.3; // 삭제/회수는 높은 위험
                break;
            case CREATE_POLICY:
            case GRANT_ACCESS:
                riskScore += 0.2; // 생성/부여는 중간 위험
                break;
            case UPDATE_POLICY:
            case OPTIMIZE_RULE:
                riskScore += 0.1; // 수정/최적화는 낮은 위험
                break;
            default:
                riskScore += 0.05;
        }
        
        // 2. 신뢰도에 따른 조정
        Double confidence = proposal.getConfidenceScore();
        if (confidence != null) {
            if (confidence < 0.5) {
                riskScore += 0.3; // 낮은 신뢰도는 위험 증가
            } else if (confidence < 0.7) {
                riskScore += 0.1;
            } else if (confidence > 0.9) {
                riskScore -= 0.1; // 높은 신뢰도는 위험 감소
            }
        }
        
        // 3. 예상 영향도에 따른 조정
        Double expectedImpact = proposal.getExpectedImpact();
        if (expectedImpact != null && expectedImpact > 0.8) {
            riskScore += 0.2; // 높은 영향도는 위험 증가
        }
        
        // 4. 학습 유형에 따른 조정
        if (proposal.getLearningType() != null) {
            switch (proposal.getLearningType()) {
                case THREAT_RESPONSE:
                    riskScore += 0.1; // 위협 대응은 신중해야 함
                    break;
                case ACCESS_PATTERN:
                    riskScore += 0.05;
                    break;
                case POLICY_FEEDBACK:
                    // 정책 피드백은 상대적으로 안전
                    break;
            }
        }
        
        // 최종 위험도 계산
        assessment.setRiskScore(riskScore);
        assessment.setAdjustedRisk(calculateAdjustedRisk(baseRisk, riskScore));
        assessment.setAssessmentTime(LocalDateTime.now());
        
        // 위험 요소 상세
        Map<String, Object> factors = new HashMap<>();
        factors.put("proposalType", proposal.getProposalType());
        factors.put("confidence", confidence);
        factors.put("expectedImpact", expectedImpact);
        factors.put("learningType", proposal.getLearningType());
        assessment.setRiskFactors(factors);
        
        log.debug("Risk assessment complete. Adjusted risk: {}", assessment.getAdjustedRisk());
        return assessment;
    }
    
    /**
     * 거버넌스 규칙 적용
     * 
     * @param proposal 제안
     * @param riskAssessment 위험 평가
     * @return 거버넌스 결정
     */
    private GovernanceDecision applyGovernanceRules(
            PolicyEvolutionProposal proposal, 
            RiskAssessment riskAssessment) {
        
        log.debug("Applying governance rules to proposal: {}", proposal.getId());
        
        PolicyEvolutionProposal.RiskLevel adjustedRisk = riskAssessment.getAdjustedRisk();
        
        // 1. 자동 승인 검사
        if (canAutoApprove(proposal, riskAssessment)) {
            log.info("Proposal {} qualifies for auto-approval", proposal.getId());
            return GovernanceDecision.builder()
                .proposalId(proposal.getId())
                .decision(DecisionType.AUTO_APPROVE)
                .riskAssessment(riskAssessment)
                .reason("Low risk with high confidence")
                .autoApproved(true)
                .build();
        }
        
        // 2. 다단계 승인 필요 여부
        if (needsMultiApproval(adjustedRisk)) {
            int requiredApprovers = calculateRequiredApprovers(adjustedRisk);
            log.info("Proposal {} requires multi-level approval ({} approvers)", 
                proposal.getId(), requiredApprovers);
            
            return GovernanceDecision.builder()
                .proposalId(proposal.getId())
                .decision(DecisionType.MULTI_APPROVAL_REQUIRED)
                .riskAssessment(riskAssessment)
                .requiredApprovers(requiredApprovers)
                .reason(String.format("%s risk requires %d approvers", adjustedRisk, requiredApprovers))
                .build();
        }
        
        // 3. 단일 승인
        log.info("Proposal {} requires single approval", proposal.getId());
        return GovernanceDecision.builder()
            .proposalId(proposal.getId())
            .decision(DecisionType.SINGLE_APPROVAL_REQUIRED)
            .riskAssessment(riskAssessment)
            .requiredApprovers(1)
            .reason("Standard approval process")
            .build();
    }
    
    /**
     * 자동 승인 가능 여부
     * 
     * @param proposal 제안
     * @param riskAssessment 위험 평가
     * @return 자동 승인 가능 여부
     */
    private boolean canAutoApprove(PolicyEvolutionProposal proposal, RiskAssessment riskAssessment) {
        if (!autoApproveEnabled) {
            return false;
        }
        
        // 위험도 확인
        PolicyEvolutionProposal.RiskLevel maxRisk = PolicyEvolutionProposal.RiskLevel.valueOf(autoApproveMaxRisk);
        if (riskAssessment.getAdjustedRisk().ordinal() > maxRisk.ordinal()) {
            return false;
        }
        
        // 신뢰도 확인
        Double confidence = proposal.getConfidenceScore();
        if (confidence == null || confidence < autoApproveMinConfidence) {
            return false;
        }
        
        // 추가 규칙 확인
        for (GovernanceRule rule : governanceRules.values()) {
            if (!rule.allows(proposal, riskAssessment)) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * 다단계 승인 필요 여부
     * 
     * @param riskLevel 위험 수준
     * @return 다단계 승인 필요 여부
     */
    private boolean needsMultiApproval(PolicyEvolutionProposal.RiskLevel riskLevel) {
        PolicyEvolutionProposal.RiskLevel threshold = 
            PolicyEvolutionProposal.RiskLevel.valueOf(multiApprovalThreshold);
        return riskLevel.ordinal() >= threshold.ordinal();
    }
    
    /**
     * 필요한 승인자 수 계산
     * 
     * @param riskLevel 위험 수준
     * @return 필요한 승인자 수
     */
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
    
    /**
     * 조정된 위험도 계산
     * 
     * @param baseRisk 기본 위험도
     * @param riskScore 위험 점수
     * @return 조정된 위험도
     */
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
    
    /**
     * 거버넌스 결정 실행
     * 
     * @param proposal 제안
     * @param decision 결정
     */
    private void executeDecision(PolicyEvolutionProposal proposal, GovernanceDecision decision) {
        log.info("Executing governance decision: {} for proposal {}", 
            decision.getDecision(), proposal.getId());
        
        try {
            switch (decision.getDecision()) {
                case AUTO_APPROVE:
                    // 자동 승인 및 활성화
                    proposal.setStatus(ProposalStatus.APPROVED);
                    proposal.setApprovedBy("SYSTEM_AUTO");
                    proposal.setReviewedAt(LocalDateTime.now());
                    proposalRepository.save(proposal);
                    
                    // 즉시 활성화
                    activationService.activatePolicy(proposal.getId(), "SYSTEM_AUTO");
                    break;
                    
                case MULTI_APPROVAL_REQUIRED:
                    // 다단계 승인 프로세스 시작
                    approvalService.initiateMultiApproval(
                        proposal.getId(), 
                        decision.getRequiredApprovers(),
                        decision.getRiskAssessment()
                    );
                    break;
                    
                case SINGLE_APPROVAL_REQUIRED:
                    // 단일 승인 프로세스 시작
                    approvalService.initiateSingleApproval(
                        proposal.getId(),
                        decision.getRiskAssessment()
                    );
                    break;
                    
                case REJECT:
                    // 제안 거부
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
    
    /**
     * 평가 가능 여부
     * 
     * @param proposal 제안
     * @return 평가 가능 여부
     */
    private boolean canEvaluate(PolicyEvolutionProposal proposal) {
        ProposalStatus status = proposal.getStatus();
        return status == ProposalStatus.PENDING || status == ProposalStatus.APPROVED;
    }
    
    /**
     * 거버넌스 이벤트 발행
     * 
     * @param proposal 제안
     * @param decision 결정
     */
    private void publishGovernanceEvent(PolicyEvolutionProposal proposal, GovernanceDecision decision) {
        GovernanceEvent event = GovernanceEvent.builder()
            .proposalId(proposal.getId())
            .decision(decision)
            .timestamp(LocalDateTime.now())
            .build();
        
        eventPublisher.publishEvent(event);
    }
    
    /**
     * 거버넌스 규칙 추가
     * 
     * @param ruleId 규칙 ID
     * @param rule 규칙
     */
    public void addGovernanceRule(String ruleId, GovernanceRule rule) {
        log.info("Adding governance rule: {}", ruleId);
        governanceRules.put(ruleId, rule);
    }
    
    /**
     * 거버넌스 규칙 제거
     * 
     * @param ruleId 규칙 ID
     */
    public void removeGovernanceRule(String ruleId) {
        log.info("Removing governance rule: {}", ruleId);
        governanceRules.remove(ruleId);
    }
    
    // ==================== Inner Classes ====================
    
    /**
     * 위험 평가
     */
    @lombok.Data
    public static class RiskAssessment {
        private PolicyEvolutionProposal.RiskLevel baseRisk;
        private PolicyEvolutionProposal.RiskLevel adjustedRisk;
        private double riskScore;
        private Map<String, Object> riskFactors;
        private LocalDateTime assessmentTime;
    }
    
    /**
     * 거버넌스 결정
     */
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
    
    /**
     * 결정 타입
     */
    public enum DecisionType {
        AUTO_APPROVE,
        SINGLE_APPROVAL_REQUIRED,
        MULTI_APPROVAL_REQUIRED,
        REJECT,
        SKIP,
        ERROR
    }
    
    /**
     * 거버넌스 규칙
     */
    public interface GovernanceRule {
        boolean allows(PolicyEvolutionProposal proposal, RiskAssessment assessment);
        String getRuleDescription();
    }
    
    /**
     * 거버넌스 이벤트
     */
    @lombok.Builder
    @lombok.Data
    public static class GovernanceEvent {
        private Long proposalId;
        private GovernanceDecision decision;
        private LocalDateTime timestamp;
    }
    
    /**
     * 거버넌스 예외
     */
    public static class GovernanceException extends RuntimeException {
        public GovernanceException(String message) {
            super(message);
        }
        
        public GovernanceException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}