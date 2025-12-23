package io.contexa.contexacore.autonomous.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Threat Assessment
 *
 * 위협 평가 결과를 나타내는 도메인 객체
 *
 * v3.1.0 변경사항:
 * - threatLevel 필드 deprecated: riskScore + action으로 대체
 * - AI Native 원칙: LLM이 action을 직접 결정, 임계값 기반 판단 제거
 *
 * @author AI Security Framework
 * @since 3.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ThreatAssessment {

    private String assessmentId;
    private String eventId;

    /**
     * @deprecated v3.1.0: riskScore + action으로 대체됨.
     *             AI Native 원칙에 따라 LLM이 action을 직접 결정하므로
     *             임계값 기반 threatLevel 분류는 더 이상 사용하지 않음.
     *             하위 호환성을 위해 유지되나 향후 버전에서 제거 예정.
     */
    @Deprecated(since = "3.1.0", forRemoval = true)
    private ThreatLevel threatLevel;
    private double riskScore;
    private String threatType;
    private String description;
    private String evaluator;
    private LocalDateTime assessedAt;
    
    // 추가 평가 정보
    private List<String> indicators;
    private List<String> tactics;
    private List<String> techniques;
    private Map<String, Object> metadata;
    
    // 권장 조치
    private List<String> recommendedActions;
    private String mitigationStrategy;
    private String strategyName;
    private int priorityScore;
    
    // 평가 신뢰도
    private double confidence;
    private String confidenceReason;

    private String action;

    // AI Native: LLM이 에스컬레이션 필요 여부를 직접 결정
    // LLM이 현재 Layer에서 충분히 분석했다고 판단하면 false
    // LLM이 더 상위 Layer 분석이 필요하다고 판단하면 true
    @Builder.Default
    private boolean shouldEscalate = false;
    
    // 추가 필드들
    @Builder.Default
    private Map<String, String> frameworkMapping = new HashMap<>();
    private LocalDateTime timestamp;

    // 패턴 정보 (Strategy 클래스들을 위한 필드)
    private Set<String> patterns;

    // reason 필드 (builder 호환성)
    private String reason;
    
    // ============================================================
    // AI Native 메서드 (riskScore + action 기반)
    // ============================================================

    /**
     * 고위험 위협 여부 (AI Native - riskScore 기반)
     *
     * @return riskScore >= 0.7 이면 true
     */
    public boolean isHighRiskByScore() {
        return riskScore >= 0.7;
    }

    /**
     * 즉각 조치 필요 여부 (AI Native - riskScore 기반)
     *
     * @return riskScore >= 0.9 이면 true
     */
    public boolean requiresImmediateActionByScore() {
        return riskScore >= 0.9;
    }

    /**
     * 자동 차단 가능 여부 (AI Native - riskScore + confidence 기반)
     *
     * @return confidence > 0.8 AND riskScore >= 0.7 이면 true
     */
    public boolean canAutoBlockByScore() {
        return confidence > 0.8 && riskScore >= 0.7;
    }

    /**
     * Get confidence score (alias for confidence field)
     */
    public double getConfidenceScore() {
        return confidence;
    }
    
    /**
     * 위협 수준 Enum
     *
     * @deprecated v3.1.0: riskScore + action으로 대체됨.
     *             AI Native 원칙에 따라 LLM이 action을 직접 결정하므로
     *             임계값 기반 ThreatLevel 분류는 더 이상 사용하지 않음.
     *             SecurityIncident 엔티티에서는 여전히 사용됨 (JPA 호환성).
     */
    @Deprecated(since = "3.1.0", forRemoval = true)
    public enum ThreatLevel {
        CRITICAL("Critical", 0.9),
        HIGH("High", 0.7),
        MEDIUM("Medium", 0.5),
        LOW("Low", 0.3),
        INFO("Info", 0.1);

        private final String description;
        private final double threshold;

        ThreatLevel(String description, double threshold) {
            this.description = description;
            this.threshold = threshold;
        }

        public String getDescription() {
            return description;
        }

        public double getThreshold() {
            return threshold;
        }
    }
}