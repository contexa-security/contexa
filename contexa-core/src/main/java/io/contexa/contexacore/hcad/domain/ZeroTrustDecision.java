package io.contexa.contexacore.hcad.domain;

import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Zero Trust 최종 결정
 *
 * AI 진단 결과 + 신뢰 프로필 + 위협 상관관계를 종합한 최종 보안 결정
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ZeroTrustDecision {
    private String analysisId;
    private String eventId;
    private String userId;
    private SecurityDecision.Action finalAction;
    private SecurityDecision.Action originalAction;
    private double currentTrustScore;
    private double previousTrustScore;
    private RiskLevel riskLevel;
    private double confidence;
    private String reasoning;
    private ThreatCorrelationResult threatCorrelation;
    private List<String> accessRecommendations;
    private ContinuousMonitoring monitoringRequirements;
    private long processingTimeMs;
    private Instant timestamp;
    private List<String> zeroTrustPrinciples;
    private Map<String, Object> metadata;

    // 호환성 메소드
    public double getTrustScore() {
        return currentTrustScore;
    }

    public List<String> getRecommendations() {
        return accessRecommendations;
    }
}
