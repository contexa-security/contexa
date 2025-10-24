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
    
    // 추가 필드들
    @Builder.Default
    private Map<String, String> frameworkMapping = new HashMap<>();
    private LocalDateTime timestamp;

    // 패턴 정보 (Strategy 클래스들을 위한 필드)
    private Set<String> patterns;

    // reason 필드 (builder 호환성)
    private String reason;
    
    /**
     * 고위험 위협 여부
     * 
     * @return 고위험이면 true
     */
    public boolean isHighRisk() {
        return threatLevel == ThreatLevel.CRITICAL ||
               threatLevel == ThreatLevel.HIGH;
    }
    
    /**
     * 즉각 조치 필요 여부
     * 
     * @return 즉각 조치가 필요하면 true
     */
    public boolean requiresImmediateAction() {
        return threatLevel == ThreatLevel.CRITICAL;
    }
    
    /**
     * 자동 차단 가능 여부
     * 
     * @return 자동 차단 가능하면 true
     */
    public boolean canAutoBlock() {
        return confidence > 0.8 && isHighRisk();
    }
    
    /**
     * Get confidence score (alias for confidence field)
     */
    public double getConfidenceScore() {
        return confidence;
    }
    
    /**
     * 위협 수준 Enum
     */
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