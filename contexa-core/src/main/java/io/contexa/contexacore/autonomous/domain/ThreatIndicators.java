package io.contexa.contexacore.autonomous.domain;

import lombok.*;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.*;

/**
 * ThreatIndicators - 위협 지표 도메인 모델
 * 
 * DynamicStrategySelector와 보안 평면에서 사용하는
 * 위협 지표를 표현하는 도메인 모델입니다.
 * 
 * @author contexa
 * @since 1.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class ThreatIndicators implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    // IOC (Indicators of Compromise) 관련
    private boolean iocPresent;
    private int iocCount;
    private List<String> iocTypes;
    private Map<String, Object> iocDetails;
    
    // MITRE ATT&CK 관련
    private boolean mitreMapping;
    private int mitreTechniques;
    private List<String> mitreTactics;
    private List<MitreIndicator> mitreIndicators;
    
    // 이상 행동 관련
    private boolean anomalyDetected;
    private double anomalyScore;
    private String anomalyType;
    private Map<String, Double> anomalyScores;
    
    // 과거 위협 관련
    private boolean historicalThreat;
    private int historicalCount;
    private List<HistoricalThreat> historicalThreats;
    
    // 위험 점수
    private double riskScore;
    private String riskLevel; // CRITICAL, HIGH, MEDIUM, LOW, INFO
    private Map<String, Double> riskFactors;
    
    // 네트워크 지표
    private NetworkIndicators networkIndicators;
    
    // 사용자 행동 지표
    private BehaviorIndicators behaviorIndicators;
    
    // 시스템 지표
    private SystemIndicators systemIndicators;
    
    // 메타데이터
    private String source;
    private LocalDateTime timestamp;
    private String detectionMethod;
    private Map<String, Object> metadata;
    
    /**
     * MITRE ATT&CK 지표
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class MitreIndicator {
        private String techniqueId;
        private String techniqueName;
        private String tacticName;
        private double confidence;
        private List<String> evidence;
    }
    
    /**
     * 과거 위협 정보
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class HistoricalThreat {
        private String threatId;
        private LocalDateTime occurredAt;
        private String threatType;
        private double severity;
        private String resolution;
        private Map<String, Object> details;
    }
    
    /**
     * 네트워크 지표
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class NetworkIndicators {
        private boolean suspiciousTraffic;
        private int unusualPortsCount;
        private List<String> blacklistedIps;
        private Map<String, Integer> protocolAnomalies;
        private double networkAnomalyScore;
        private List<NetworkAnomaly> anomalies;
    }
    
    /**
     * 네트워크 이상 징후
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class NetworkAnomaly {
        private String anomalyType;
        private String sourceIp;
        private String destinationIp;
        private int port;
        private String protocol;
        private double severity;
        private LocalDateTime detectedAt;
    }
    
    /**
     * 사용자 행동 지표
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class BehaviorIndicators {
        private boolean unusualActivity;
        private double deviationScore;
        private List<String> suspiciousActions;
        private Map<String, Integer> activityPatterns;
        private List<BehaviorAnomaly> anomalies;
        private String riskProfile;
    }
    
    /**
     * 행동 이상 징후
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class BehaviorAnomaly {
        private String anomalyType;
        private String action;
        private double deviationFromBaseline;
        private LocalDateTime occurredAt;
        private Map<String, Object> context;
    }
    
    /**
     * 시스템 지표
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SystemIndicators {
        private boolean processAnomaly;
        private boolean fileSystemAnomaly;
        private boolean registryAnomaly;
        private double cpuAnomalyScore;
        private double memoryAnomalyScore;
        private List<SystemAnomaly> anomalies;
        private Map<String, Object> resourceMetrics;
    }
    
    /**
     * 시스템 이상 징후
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SystemAnomaly {
        private String anomalyType;
        private String component;
        private String description;
        private double severity;
        private LocalDateTime detectedAt;
        private Map<String, Object> details;
    }
    
    /**
     * 위험 수준 계산
     */
    public String calculateRiskLevel() {
        if (riskScore >= 90) return "CRITICAL";
        if (riskScore >= 70) return "HIGH";
        if (riskScore >= 50) return "MEDIUM";
        if (riskScore >= 30) return "LOW";
        return "INFO";
    }
    
    /**
     * AI Native v3.3.0: 규칙 기반 점수 계산 제거
     *
     * 원시 데이터(iocCount, mitreTechniques, anomalyScore 등)를
     * LLM에게 직접 전달하여 분석하도록 변경
     *
     * @return 기존 호환성을 위해 anomalyScore 반환 (LLM이 최종 판단)
     */
    public double calculateThreatScore() {
        // AI Native: 규칙 기반 가중치 계산 제거
        // LLM이 toSummary()의 원시 데이터를 분석하여 직접 판단
        return anomalyScore;
    }
    
    /**
     * 위협 유형 판별
     */
    public Set<String> identifyThreatTypes() {
        Set<String> threatTypes = new HashSet<>();
        
        if (mitreMapping && mitreTactics != null) {
            if (mitreTactics.contains("Initial Access")) {
                threatTypes.add("INTRUSION_ATTEMPT");
            }
            if (mitreTactics.contains("Persistence")) {
                threatTypes.add("PERSISTENCE_MECHANISM");
            }
            if (mitreTactics.contains("Exfiltration")) {
                threatTypes.add("DATA_EXFILTRATION");
            }
        }
        
        if (networkIndicators != null && networkIndicators.suspiciousTraffic) {
            threatTypes.add("NETWORK_ATTACK");
        }
        
        if (behaviorIndicators != null && behaviorIndicators.unusualActivity) {
            threatTypes.add("INSIDER_THREAT");
        }
        
        if (systemIndicators != null && systemIndicators.processAnomaly) {
            threatTypes.add("MALWARE");
        }
        
        if (iocPresent && iocTypes != null) {
            if (iocTypes.contains("malicious_ip")) {
                threatTypes.add("KNOWN_THREAT");
            }
            if (iocTypes.contains("malicious_domain")) {
                threatTypes.add("C2_COMMUNICATION");
            }
        }
        
        return threatTypes;
    }
    
    /**
     * 긴급도 판별
     */
    public int getUrgencyLevel() {
        int urgency = 0;
        
        // 위험 점수 기반
        if (riskScore >= 80) urgency = 5;
        else if (riskScore >= 60) urgency = 4;
        else if (riskScore >= 40) urgency = 3;
        else if (riskScore >= 20) urgency = 2;
        else urgency = 1;
        
        // 특정 지표가 있으면 긴급도 상향
        if (mitreMapping && mitreTactics != null && 
            (mitreTactics.contains("Exfiltration") || mitreTactics.contains("Impact"))) {
            urgency = Math.min(urgency + 2, 5);
        }
        
        if (networkIndicators != null && networkIndicators.blacklistedIps != null && 
            !networkIndicators.blacklistedIps.isEmpty()) {
            urgency = Math.min(urgency + 1, 5);
        }
        
        return urgency;
    }
    
    /**
     * 대응 권장사항 생성
     */
    public List<String> generateRecommendations() {
        List<String> recommendations = new ArrayList<>();
        
        if (iocPresent) {
            recommendations.add("IOC 기반 차단 규칙 적용");
            recommendations.add("관련 시스템 격리 검토");
        }
        
        if (mitreMapping) {
            recommendations.add("MITRE 기반 대응 방안 적용");
            if (mitreTactics != null && mitreTactics.contains("Persistence")) {
                recommendations.add("시스템 지속성 메커니즘 제거");
            }
        }
        
        if (networkIndicators != null && networkIndicators.suspiciousTraffic) {
            recommendations.add("네트워크 트래픽 모니터링 강화");
            recommendations.add("의심스러운 IP 차단");
        }
        
        if (behaviorIndicators != null && behaviorIndicators.unusualActivity) {
            recommendations.add("사용자 계정 권한 검토");
            recommendations.add("추가 인증 요구");
        }
        
        if (systemIndicators != null && systemIndicators.processAnomaly) {
            recommendations.add("의심스러운 프로세스 종료");
            recommendations.add("시스템 전체 스캔 실행");
        }
        
        return recommendations;
    }
    
    /**
     * JSON 형식으로 요약 정보 반환
     */
    public Map<String, Object> toSummary() {
        Map<String, Object> summary = new HashMap<>();
        
        summary.put("threatScore", calculateThreatScore());
        summary.put("riskLevel", calculateRiskLevel());
        summary.put("urgencyLevel", getUrgencyLevel());
        summary.put("threatTypes", identifyThreatTypes());
        summary.put("iocCount", iocCount);
        summary.put("mitreTechniques", mitreTechniques);
        summary.put("anomalyScore", anomalyScore);
        summary.put("timestamp", timestamp);
        summary.put("source", source);
        
        return summary;
    }
}