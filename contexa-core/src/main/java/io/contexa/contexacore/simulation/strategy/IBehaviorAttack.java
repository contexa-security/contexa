package io.contexa.contexacore.simulation.strategy;

import io.contexa.contexacore.simulation.domain.UserBehaviorPattern;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * 행동 기반 공격 전략 인터페이스
 * 
 * 사용자 행동 패턴을 모방하거나 이상 행동을 생성하는 공격을 정의합니다.
 * Impossible Travel, 비정상 접근 패턴, Zero Trust 위반 등을 포함합니다.
 * 
 * @author AI3Security
 * @since 1.0.0
 */
public interface IBehaviorAttack extends IAttackStrategy {
    
    /**
     * 사용자 행동 모방
     * 
     * @param pattern 모방할 행동 패턴
     * @return 모방 결과
     */
    BehaviorResult mimicBehavior(UserBehaviorPattern pattern);
    
    /**
     * Impossible Travel 공격
     * 
     * @param userId 사용자 ID
     * @param locations 위치 목록
     * @param timeIntervals 시간 간격 (초)
     * @return 공격 결과
     */
    BehaviorResult performImpossibleTravel(String userId, List<Location> locations, List<Integer> timeIntervals);
    
    /**
     * 비정상 시간대 접근
     * 
     * @param userId 사용자 ID
     * @param accessTime 접근 시간
     * @return 공격 결과
     */
    BehaviorResult performAbnormalTimeAccess(String userId, LocalDateTime accessTime);
    
    /**
     * 장치 신뢰도 위반
     * 
     * @param userId 사용자 ID
     * @param deviceFingerprint 장치 지문
     * @return 공격 결과
     */
    BehaviorResult violateDeviceTrust(String userId, String deviceFingerprint);
    
    /**
     * 대량 데이터 접근 패턴
     * 
     * @param userId 사용자 ID
     * @param dataVolume 데이터 양 (바이트)
     * @param duration 기간 (초)
     * @return 공격 결과
     */
    BehaviorResult performMassDataAccess(String userId, long dataVolume, int duration);
    
    /**
     * 비정상 네트워크 패턴
     * 
     * @param userId 사용자 ID
     * @param networkPattern 네트워크 패턴
     * @return 공격 결과
     */
    BehaviorResult generateAnomalousNetworkPattern(String userId, NetworkPattern networkPattern);
    
    /**
     * 계정 탈취 행동 시뮬레이션
     * 
     * @param legitimatePattern 정상 패턴
     * @param attackerPattern 공격자 패턴
     * @return 탈취 시뮬레이션 결과
     */
    BehaviorResult simulateAccountTakeover(UserBehaviorPattern legitimatePattern, 
                                          UserBehaviorPattern attackerPattern);
    
    /**
     * 내부자 위협 패턴
     * 
     * @param userId 사용자 ID
     * @param threatIndicators 위협 지표
     * @return 내부자 위협 결과
     */
    BehaviorResult generateInsiderThreat(String userId, List<ThreatIndicator> threatIndicators);
    
    /**
     * 행동 공격 결과
     */
    class BehaviorResult {
        private boolean anomalyDetected;
        private String anomalyType;
        private double anomalyScore;
        private Map<String, Double> behaviorScores;
        private List<String> violatedPolicies;
        private boolean zeroTrustViolation;
        private String riskAssessment;
        private Map<String, Object> evidences;
        
        // Getters and Setters
        public boolean isAnomalyDetected() { return anomalyDetected; }
        public void setAnomalyDetected(boolean anomalyDetected) { 
            this.anomalyDetected = anomalyDetected; 
        }
        
        public String getAnomalyType() { return anomalyType; }
        public void setAnomalyType(String anomalyType) { this.anomalyType = anomalyType; }
        
        public double getAnomalyScore() { return anomalyScore; }
        public void setAnomalyScore(double anomalyScore) { this.anomalyScore = anomalyScore; }
        
        public Map<String, Double> getBehaviorScores() { return behaviorScores; }
        public void setBehaviorScores(Map<String, Double> behaviorScores) { 
            this.behaviorScores = behaviorScores; 
        }
        
        public List<String> getViolatedPolicies() { return violatedPolicies; }
        public void setViolatedPolicies(List<String> violatedPolicies) { 
            this.violatedPolicies = violatedPolicies; 
        }
        
        public boolean isZeroTrustViolation() { return zeroTrustViolation; }
        public void setZeroTrustViolation(boolean zeroTrustViolation) { 
            this.zeroTrustViolation = zeroTrustViolation; 
        }
        
        public String getRiskAssessment() { return riskAssessment; }
        public void setRiskAssessment(String riskAssessment) { 
            this.riskAssessment = riskAssessment; 
        }
        
        public Map<String, Object> getEvidences() { return evidences; }
        public void setEvidences(Map<String, Object> evidences) { this.evidences = evidences; }
    }
    
    /**
     * 위치 정보
     */
    class Location {
        private String country;
        private String city;
        private double latitude;
        private double longitude;
        private String ipAddress;
        private String timezone;
        
        public Location() {}
        
        public Location(String country, String city, double latitude, double longitude) {
            this.country = country;
            this.city = city;
            this.latitude = latitude;
            this.longitude = longitude;
        }
        
        // Getters and Setters
        public String getCountry() { return country; }
        public void setCountry(String country) { this.country = country; }
        
        public String getCity() { return city; }
        public void setCity(String city) { this.city = city; }
        
        public double getLatitude() { return latitude; }
        public void setLatitude(double latitude) { this.latitude = latitude; }
        
        public double getLongitude() { return longitude; }
        public void setLongitude(double longitude) { this.longitude = longitude; }
        
        public String getIpAddress() { return ipAddress; }
        public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
        
        public String getTimezone() { return timezone; }
        public void setTimezone(String timezone) { this.timezone = timezone; }
    }
    
    /**
     * 네트워크 패턴
     */
    class NetworkPattern {
        private List<String> accessedIps;
        private Map<Integer, Integer> portUsage; // port -> count
        private String protocol;
        private long totalBandwidth;
        private int connectionCount;
        private List<String> unusualPorts;
        private boolean torUsage;
        private boolean vpnUsage;
        
        // Getters and Setters
        public List<String> getAccessedIps() { return accessedIps; }
        public void setAccessedIps(List<String> accessedIps) { this.accessedIps = accessedIps; }
        
        public Map<Integer, Integer> getPortUsage() { return portUsage; }
        public void setPortUsage(Map<Integer, Integer> portUsage) { this.portUsage = portUsage; }
        
        public String getProtocol() { return protocol; }
        public void setProtocol(String protocol) { this.protocol = protocol; }
        
        public long getTotalBandwidth() { return totalBandwidth; }
        public void setTotalBandwidth(long totalBandwidth) { this.totalBandwidth = totalBandwidth; }
        
        public int getConnectionCount() { return connectionCount; }
        public void setConnectionCount(int connectionCount) { 
            this.connectionCount = connectionCount; 
        }
        
        public List<String> getUnusualPorts() { return unusualPorts; }
        public void setUnusualPorts(List<String> unusualPorts) { this.unusualPorts = unusualPorts; }
        
        public boolean isTorUsage() { return torUsage; }
        public void setTorUsage(boolean torUsage) { this.torUsage = torUsage; }
        
        public boolean isVpnUsage() { return vpnUsage; }
        public void setVpnUsage(boolean vpnUsage) { this.vpnUsage = vpnUsage; }
    }
    
    /**
     * 위협 지표
     */
    enum ThreatIndicator {
        DATA_EXFILTRATION("Large data downloads outside normal pattern"),
        PRIVILEGE_ABUSE("Using elevated privileges unnecessarily"),
        LATERAL_MOVEMENT("Accessing systems outside normal scope"),
        PERSISTENCE_CREATION("Creating backdoors or scheduled tasks"),
        LOG_DELETION("Attempting to delete audit logs"),
        SHADOW_IT("Using unauthorized tools or services"),
        POLICY_VIOLATION("Repeated security policy violations"),
        ABNORMAL_HOURS("Working at unusual hours consistently"),
        HIGH_FAILURE_RATE("High rate of access failures"),
        RECONNAISSANCE("Scanning or probing internal systems");
        
        private final String description;
        
        ThreatIndicator(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
}