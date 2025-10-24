package io.contexa.contexacore.autonomous.tiered.routing;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * 공격 패턴 정보
 * 
 * Redis에 저장될 공격 패턴 데이터 모델입니다.
 * 실시간 위협 탐지와 차단에 사용됩니다.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AttackPattern implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    /**
     * 공격 소스 IP 주소
     */
    private String sourceIp;
    
    /**
     * 공격 패턴 (페이로드, 시그니처 등)
     */
    private String pattern;
    
    /**
     * 공격 유형 (BRUTE_FORCE, SQL_INJECTION, XSS, DDoS 등)
     */
    private String attackType;
    
    /**
     * 심각도 (LOW, MEDIUM, HIGH, CRITICAL)
     */
    private String severity;
    
    /**
     * 탐지 시각
     */
    private LocalDateTime detectedAt;
    
    /**
     * 마지막 활동 시각
     */
    private LocalDateTime lastSeenAt;
    
    /**
     * 공격 시도 횟수
     */
    private int attemptCount;
    
    /**
     * 활성 상태 (true: 활성, false: 비활성)
     */
    private boolean active;
    
    /**
     * 비활성화 시각
     */
    private LocalDateTime deactivatedAt;
    
    /**
     * 차단 여부
     */
    private boolean blocked;
    
    /**
     * 차단 시작 시각
     */
    private LocalDateTime blockedAt;
    
    /**
     * 차단 만료 시각
     */
    private LocalDateTime blockExpiresAt;
    
    /**
     * 신뢰도 점수 (0.0 ~ 1.0)
     */
    private double confidenceScore;
    
    /**
     * MITRE ATT&CK 매핑
     */
    private String mitreTactic;
    private String mitreTechnique;
    
    /**
     * 추가 메타데이터 (JSON 형식)
     */
    private String metadata;
    
    /**
     * 활성 상태 확인
     */
    public boolean isActive() {
        return active && !isExpired();
    }
    
    /**
     * 만료 여부 확인
     */
    public boolean isExpired() {
        if (blockExpiresAt == null) {
            return false;
        }
        return LocalDateTime.now().isAfter(blockExpiresAt);
    }
    
    /**
     * 차단 필요 여부 확인
     */
    public boolean shouldBlock() {
        return blocked && isActive() && !isExpired();
    }
    
    /**
     * 공격 시도 증가
     */
    public void incrementAttempt() {
        this.attemptCount++;
        this.lastSeenAt = LocalDateTime.now();
    }
}