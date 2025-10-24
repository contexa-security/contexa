package io.contexa.contexaidentity.security.core.mfa;

/**
 * 리스크 평가 결과 객체.
 */
public class RiskAssessmentResult {
    private final int score;
    private final boolean highRisk;

    public RiskAssessmentResult(int score, boolean highRisk) {
        this.score = score;
        this.highRisk = highRisk;
    }

    /** 리스크 점수 (0~100) */
    public int getScore() {
        return score;
    }

    /** highRisk=true 이면 추가 인증 또는 차단 로직을 트리거 */
    public boolean isHighRisk() {
        return highRisk;
    }
}
