package io.contexa.contexacore.autonomous.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * User Security Context
 *
 * Zero Trust 아키텍처를 위한 사용자별 보안 컨텍스트
 * 사용자의 모든 세션과 행동 패턴을 누적하여 추적합니다.
 *
 * 이 클래스는 AI가 사용자의 과거-현재-미래 행동을 분석하고
 * 지속적인 위협 평가를 수행할 수 있도록 합니다.
 *
 * @author AI Security Framework
 * @since 3.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
public class UserSecurityContext {
    
    /**
     * 사용자 고유 식별자 (필수)
     * Zero Trust의 핵심 - 모든 컨텍스트의 기준점
     */
    private String userId;
    
    /**
     * 사용자명
     */
    private String userName;
    
    /**
     * 조직 ID
     */
    private String organizationId;
    
    /**
     * 현재 활성 세션 목록
     * 사용자가 동시에 여러 세션을 가질 수 있음
     */
    @Builder.Default
    private List<SessionContext> activeSessions = new ArrayList<>();
    
    /**
     * 사용자 행동 패턴
     * AI가 학습하고 분석하는 누적 데이터
     */
    @Builder.Default
    private Map<String, String> behaviorPatterns = new HashMap<>();
    
    /**
     * 위협 지표
     * 사용자와 관련된 모든 위협 신호
     */
    @Builder.Default
    private Map<String, String> threatIndicators = new HashMap<>();
    
    /**
     * 현재 위협 점수
     * 0.0 (완전 안전) ~ 1.0 (완전 위험)
     * Trust Score = 1.0 - Threat Score
     */
    @Builder.Default
    private Double currentThreatScore = 0.5;
    
    /**
     * 마지막 활동 시간
     */
    @Builder.Default
    private LocalDateTime lastActivity = LocalDateTime.now();
    
    /**
     * 실패 카운터
     * 각종 실패 시도 횟수 추적
     */
    @Builder.Default
    private Map<String, Integer> failureCounters = new HashMap<>();
    
    /**
     * 접근 패턴 이력
     * 시간대별, 위치별 접근 패턴
     */
    @Builder.Default
    private Map<String, String> accessPatterns = new HashMap<>();
    
    /**
     * 현재 IP 주소
     * 사용자의 현재 접속 IP
     */
    private String currentIp;
    
    /**
     * 디바이스 핑거프린트
     * 사용자 디바이스의 고유 식별자
     */
    private String deviceFingerprint;
    
    /**
     * 권한 변경 이력
     */
    @Builder.Default
    private List<PermissionChange> permissionHistory = new ArrayList<>();
    
    /**
     * 위험 레벨
     */
    @Builder.Default
    private RiskLevel riskLevel = RiskLevel.MEDIUM;
    
    /**
     * MFA 상태
     */
    private MfaStatus mfaStatus;
    
    /**
     * 컨텍스트 생성 시간
     */
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();
    
    /**
     * 컨텍스트 최종 업데이트 시간
     */
    @Builder.Default
    private LocalDateTime updatedAt = LocalDateTime.now();
    
    /**
     * 세션 컨텍스트
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
    public static class SessionContext {
        private String sessionId;
        private String sourceIp;
        private String userAgent;
        private LocalDateTime startTime;
        private LocalDateTime lastAccessTime;
        private boolean active;
    }
    
    /**
     * 권한 변경 이력
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
    public static class PermissionChange {
        private LocalDateTime timestamp;
        private String changeType; // GRANT, REVOKE, MODIFY
        private String permission;
        private String reason;
        private String approvedBy;
    }
    
    /**
     * MFA 상태
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
    public static class MfaStatus {
        private boolean enabled;
        private String method; // SMS, TOTP, FIDO2, etc.
        private LocalDateTime lastVerified;
        private int failedAttempts;
    }
    
    /**
     * 위험 레벨
     */
    public enum RiskLevel {
        CRITICAL(1.0),
        HIGH(0.8),
        MEDIUM(0.5),
        LOW(0.3),
        MINIMAL(0.1);
        
        private final double score;
        
        RiskLevel(double score) {
            this.score = score;
        }
        
        public double getScore() {
            return score;
        }
        
        public static RiskLevel fromThreatScore(double threatScore) {
            if (threatScore >= 0.8) return CRITICAL;
            if (threatScore >= 0.6) return HIGH;
            if (threatScore >= 0.4) return MEDIUM;
            if (threatScore >= 0.2) return LOW;
            return MINIMAL;
        }
    }
    
    /**
     * 새 세션 추가
     */
    public void addSession(SessionContext session) {
        if (activeSessions == null) {
            activeSessions = new ArrayList<>();
        }
        // 중복 체크
        activeSessions.removeIf(s -> s.getSessionId().equals(session.getSessionId()));
        activeSessions.add(session);
        updateLastActivity();
    }
    
    /**
     * 세션 제거
     */
    public void removeSession(String sessionId) {
        if (activeSessions != null) {
            activeSessions.removeIf(s -> s.getSessionId().equals(sessionId));
        }
        updateLastActivity();
    }
    
    /**
     * 활성 세션 확인
     */
    public boolean hasActiveSession(String sessionId) {
        return activeSessions != null && 
               activeSessions.stream()
                   .anyMatch(s -> s.getSessionId().equals(sessionId) && s.isActive());
    }
    
    /**
     * 행동 패턴 추가
     */
    public void addBehaviorPattern(String key, String value) {
        if (behaviorPatterns == null) {
            behaviorPatterns = new HashMap<>();
        }
        behaviorPatterns.put(key, value);
        updateLastActivity();
    }
    
    /**
     * 위협 지표 추가
     */
    public void addThreatIndicator(String key, String value) {
        if (threatIndicators == null) {
            threatIndicators = new HashMap<>();
        }
        threatIndicators.put(key, value);
        updateLastActivity();
    }
    
    /**
     * 실패 카운터 증가
     */
    public void incrementFailureCounter(String type) {
        if (failureCounters == null) {
            failureCounters = new HashMap<>();
        }
        failureCounters.merge(type, 1, Integer::sum);
        updateLastActivity();
    }
    
    /**
     * 실패 카운터 리셋
     */
    public void resetFailureCounter(String type) {
        if (failureCounters != null) {
            failureCounters.remove(type);
        }
    }
    
    /**
     * 위협 점수 업데이트
     */
    public void updateThreatScore(double score) {
        this.currentThreatScore = Math.max(0.0, Math.min(1.0, score));
        this.riskLevel = RiskLevel.fromThreatScore(currentThreatScore);
        updateLastActivity();
    }
    
    /**
     * Trust Score 계산 (Trust = 1.0 - Threat)
     */
    public double getCurrentTrustScore() {
        return 1.0 - currentThreatScore;
    }
    
    /**
     * 마지막 활동 시간 업데이트
     */
    private void updateLastActivity() {
        this.lastActivity = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }
    
    /**
     * MFA 필요 여부
     */
    public boolean requiresMfa() {
        // AI Native: RiskLevel 기반 판단
        boolean highRisk = riskLevel == RiskLevel.HIGH || riskLevel == RiskLevel.CRITICAL;
        return highRisk ||
               (mfaStatus != null && !mfaStatus.isEnabled()) ||
               (failureCounters != null && failureCounters.values().stream().anyMatch(c -> c > 3));
    }
    
    /**
     * 세션 무효화 필요 여부
     */
    public boolean requiresSessionInvalidation() {
        return riskLevel == RiskLevel.CRITICAL ||
               (failureCounters != null && failureCounters.values().stream().anyMatch(c -> c > 5));
    }
}