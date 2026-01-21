package io.contexa.contexacore.autonomous.domain;

import lombok.*;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class ThreatIndicators implements Serializable {
    
    private static final long serialVersionUID = 1L;

    private boolean iocPresent;
    private int iocCount;
    private List<String> iocTypes;
    private Map<String, Object> iocDetails;

    private boolean mitreMapping;
    private int mitreTechniques;
    private List<String> mitreTactics;
    private List<MitreIndicator> mitreIndicators;

    private boolean anomalyDetected;
    private double anomalyScore;
    private String anomalyType;
    private Map<String, Double> anomalyScores;

    private boolean historicalThreat;
    private int historicalCount;
    private List<HistoricalThreat> historicalThreats;

    private double riskScore;
    private String riskLevel; 
    private Map<String, Double> riskFactors;

    private NetworkIndicators networkIndicators;

    private BehaviorIndicators behaviorIndicators;

    private SystemIndicators systemIndicators;

    private String source;
    private LocalDateTime timestamp;
    private String detectionMethod;
    private Map<String, Object> metadata;

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

    public String calculateRiskLevel() {
        if (riskScore >= 90) return "CRITICAL";
        if (riskScore >= 70) return "HIGH";
        if (riskScore >= 50) return "MEDIUM";
        if (riskScore >= 30) return "LOW";
        return "INFO";
    }

    public double calculateThreatScore() {

        return anomalyScore;
    }

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

    public int getUrgencyLevel() {
        int urgency = 0;

        if (riskScore >= 80) urgency = 5;
        else if (riskScore >= 60) urgency = 4;
        else if (riskScore >= 40) urgency = 3;
        else if (riskScore >= 20) urgency = 2;
        else urgency = 1;

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