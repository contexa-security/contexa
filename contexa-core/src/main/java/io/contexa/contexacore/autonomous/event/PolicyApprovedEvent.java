package io.contexa.contexacore.autonomous.event;

import org.springframework.context.ApplicationEvent;

/**
 * 자율 학습 시스템에서 생성한 정책이 승인되었을 때 발생하는 이벤트
 *
 * 이 이벤트는 AutonomousLearningCoordinator에서 발행되어
 * AIAM 시스템으로 전달되어 실제 보안 정책을 업데이트합니다.
 *
 * @author AI3Security
 * @since 1.0.0
 */
public class PolicyApprovedEvent extends ApplicationEvent {

    private final String policyId;
    private final String policyName;
    private final String policyDescription;
    private final String policyRules;
    private final String approvedBy;
    private final String targetSystem;
    private final double confidenceScore;

    /**
     * 정책 승인 이벤트 생성자
     *
     * @param source 이벤트 발생 소스
     * @param policyId 정책 ID
     * @param policyName 정책 이름
     * @param policyDescription 정책 설명
     * @param policyRules 정책 규칙 (JSON 형태)
     * @param approvedBy 승인자 (system/human/ai)
     * @param targetSystem 적용 대상 시스템
     * @param confidenceScore 정책 신뢰도 점수
     */
    public PolicyApprovedEvent(Object source, String policyId, String policyName,
                              String policyDescription, String policyRules,
                              String approvedBy, String targetSystem, double confidenceScore) {
        super(source);
        this.policyId = policyId;
        this.policyName = policyName;
        this.policyDescription = policyDescription;
        this.policyRules = policyRules;
        this.approvedBy = approvedBy;
        this.targetSystem = targetSystem;
        this.confidenceScore = confidenceScore;
    }

    // Getters
    public String getPolicyId() {
        return policyId;
    }

    public String getPolicyName() {
        return policyName;
    }

    public String getPolicyDescription() {
        return policyDescription;
    }

    public String getPolicyRules() {
        return policyRules;
    }

    public String getApprovedBy() {
        return approvedBy;
    }

    public String getTargetSystem() {
        return targetSystem;
    }

    public double getConfidenceScore() {
        return confidenceScore;
    }

    @Override
    public String toString() {
        return String.format("PolicyApprovedEvent[id=%s, name=%s, approvedBy=%s, target=%s, confidence=%.2f]",
            policyId, policyName, approvedBy, targetSystem, confidenceScore);
    }
}