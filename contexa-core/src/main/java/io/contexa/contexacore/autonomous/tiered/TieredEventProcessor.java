package io.contexa.contexacore.autonomous.tiered;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthenticationSuccessEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthenticationFailureEvent;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 계층적 이벤트 처리 프로세서
 * 
 * 이벤트를 중요도와 긴급도에 따라 3개 계층으로 분류하여 처리합니다.
 * 이를 통해 수백만 사용자의 이벤트를 효율적으로 처리할 수 있습니다.
 */
@Slf4j
@Component
public class TieredEventProcessor {
    
    @Value("${security.event.tier.critical.max-latency-ms:100}")
    private int criticalMaxLatencyMs;
    
    @Value("${security.event.tier.contextual.max-latency-ms:1000}")
    private int contextualMaxLatencyMs;
    
    @Value("${security.event.tier.general.max-latency-ms:10000}")
    private int generalMaxLatencyMs;
    
    @Value("${security.event.tier.general.sampling-rate:0.1}")
    private double generalSamplingRate;
    
    // 메트릭
    private final Map<EventTier, AtomicLong> tierCounters = new ConcurrentHashMap<>();
    
    public TieredEventProcessor() {
        for (EventTier tier : EventTier.values()) {
            tierCounters.put(tier, new AtomicLong(0));
        }
    }
    
    /**
     * 이벤트 계층 결정
     */
    public EventTier determineTier(SecurityEvent event) {
        // Critical: 즉시 처리가 필요한 고위험 이벤트
        if (isCriticalEvent(event)) {
            tierCounters.get(EventTier.CRITICAL).incrementAndGet();
            return EventTier.CRITICAL;
        }
        
        // Contextual: 중요한 컨텍스트 정보를 담은 이벤트
        if (isContextualEvent(event)) {
            tierCounters.get(EventTier.CONTEXTUAL).incrementAndGet();
            return EventTier.CONTEXTUAL;
        }
        
        // General: 일반 활동 로그
        tierCounters.get(EventTier.GENERAL).incrementAndGet();
        return EventTier.GENERAL;
    }
    
    /**
     * 인증 성공 이벤트 계층 결정
     */
    public EventTier determineTier(AuthenticationSuccessEvent event) {
        // 고위험 인증은 Critical
        if (event.calculateRiskLevel() == AuthenticationSuccessEvent.RiskLevel.CRITICAL ||
            event.calculateRiskLevel() == AuthenticationSuccessEvent.RiskLevel.HIGH ||
            event.isAnomalyDetected()) {
            tierCounters.get(EventTier.CRITICAL).incrementAndGet();
            return EventTier.CRITICAL;
        }
        
        // MFA 완료나 중간 위험은 Contextual
        if (event.isMfaCompleted() || 
            event.calculateRiskLevel() == AuthenticationSuccessEvent.RiskLevel.MEDIUM) {
            tierCounters.get(EventTier.CONTEXTUAL).incrementAndGet();
            return EventTier.CONTEXTUAL;
        }
        
        // 일반 로그인은 General
        tierCounters.get(EventTier.GENERAL).incrementAndGet();
        return EventTier.GENERAL;
    }
    
    /**
     * 인증 실패 이벤트 계층 결정
     */
    public EventTier determineTier(AuthenticationFailureEvent event) {
        // 공격 패턴은 Critical
        if (event.determineAttackType() == AuthenticationFailureEvent.AttackType.BRUTE_FORCE ||
            event.determineAttackType() == AuthenticationFailureEvent.AttackType.CREDENTIAL_STUFFING ||
            event.determineAttackType() == AuthenticationFailureEvent.AttackType.SUSTAINED_ATTACK) {
            tierCounters.get(EventTier.CRITICAL).incrementAndGet();
            return EventTier.CRITICAL;
        }
        
        // 의심스러운 활동은 Contextual
        if (event.determineAttackType() == AuthenticationFailureEvent.AttackType.SUSPICIOUS ||
            event.getFailureCount() > 3) {
            tierCounters.get(EventTier.CONTEXTUAL).incrementAndGet();
            return EventTier.CONTEXTUAL;
        }
        
        // 일반 실패는 General
        tierCounters.get(EventTier.GENERAL).incrementAndGet();
        return EventTier.GENERAL;
    }
    
    /**
     * Critical 이벤트 판단
     */
    private boolean isCriticalEvent(SecurityEvent event) {
        // 심각도가 CRITICAL 또는 HIGH
        if (event.getSeverity() == SecurityEvent.Severity.CRITICAL ||
            event.getSeverity() == SecurityEvent.Severity.HIGH) {
            return true;
        }
        
        // 특정 이벤트 타입들
        switch (event.getEventType()) {
            case PRIVILEGE_ESCALATION:
            case INTRUSION_SUCCESS:
            case DATA_EXFILTRATION:
            case SYSTEM_COMPROMISE:
            case MALWARE_DETECTED:
            case THREAT_DETECTED:
                return true;
            case AUTH_FAILURE:
                // 연속된 인증 실패
                Integer failCount = (Integer) event.getMetadata().get("failureCount");
                return failCount != null && failCount > 5;
            default:
                break;
        }
        
        // 차단된 이벤트
        return event.isBlocked();
    }
    
    /**
     * Contextual 이벤트 판단
     */
    private boolean isContextualEvent(SecurityEvent event) {
        // 중간 심각도
        if (event.getSeverity() == SecurityEvent.Severity.MEDIUM) {
            return true;
        }
        
        // 특정 이벤트 타입들
        switch (event.getEventType()) {
            case AUTH_SUCCESS:  // Zero Trust를 위해 모든 성공 인증은 최소 Contextual
            case ANOMALY_DETECTED:
            case SUSPICIOUS_ACTIVITY:
            case POLICY_VIOLATION:
            case CONFIGURATION_CHANGE:
                return true;
            default:
                break;
        }
        
        // 세션 변경이나 위치 변경
        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null) {
            if (metadata.containsKey("sessionChange") || 
                metadata.containsKey("locationChange") ||
                metadata.containsKey("deviceChange")) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * 계층별 처리 설정
     */
    public TierConfiguration getConfiguration(EventTier tier) {
        TierConfiguration config = new TierConfiguration();
        
        switch (tier) {
            case CRITICAL:
                config.setMaxLatencyMs(criticalMaxLatencyMs);
                config.setChannels(new String[]{"redis", "kafka"});
                config.setPriority(TierPriority.IMMEDIATE);
                config.setSamplingRate(1.0);  // 100% 처리
                config.setAsync(false);  // 동기 처리
                break;
                
            case CONTEXTUAL:
                config.setMaxLatencyMs(contextualMaxLatencyMs);
                config.setChannels(new String[]{"kafka", "redis"});
                config.setPriority(TierPriority.HIGH);
                config.setSamplingRate(1.0);  // 100% 처리
                config.setAsync(true);  // 비동기 처리
                break;
                
            case GENERAL:
                config.setMaxLatencyMs(generalMaxLatencyMs);
                config.setChannels(new String[]{"kafka"});
                config.setPriority(TierPriority.NORMAL);
                config.setSamplingRate(generalSamplingRate);  // 샘플링 적용
                config.setAsync(true);  // 비동기 처리
                config.setBatching(true);  // 배치 처리
                break;
        }
        
        return config;
    }
    
    /**
     * 샘플링 결정
     */
    public boolean shouldProcess(EventTier tier, SecurityEvent event) {
        TierConfiguration config = getConfiguration(tier);
        
        // Critical과 Contextual은 항상 처리
        if (tier == EventTier.CRITICAL || tier == EventTier.CONTEXTUAL) {
            return true;
        }
        
        // General은 샘플링 적용
        return Math.random() < config.getSamplingRate();
    }
    
    /**
     * 메트릭 조회
     */
    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new ConcurrentHashMap<>();
        
        for (Map.Entry<EventTier, AtomicLong> entry : tierCounters.entrySet()) {
            metrics.put(entry.getKey().name().toLowerCase() + "_count", entry.getValue().get());
        }
        
        // 계층별 비율 계산
        long total = tierCounters.values().stream()
            .mapToLong(AtomicLong::get)
            .sum();
        
        if (total > 0) {
            for (EventTier tier : EventTier.values()) {
                double percentage = (tierCounters.get(tier).get() * 100.0) / total;
                metrics.put(tier.name().toLowerCase() + "_percentage", percentage);
            }
        }
        
        metrics.put("total_events", total);
        
        return metrics;
    }
    
    /**
     * 이벤트 계층
     */
    public enum EventTier {
        CRITICAL,    // Level 1: 즉시 처리 필요
        CONTEXTUAL,  // Level 2: 중요 컨텍스트
        GENERAL      // Level 3: 일반 로그
    }
    
    /**
     * 계층 우선순위
     */
    public enum TierPriority {
        IMMEDIATE,   // 즉시 처리
        HIGH,        // 높은 우선순위
        NORMAL       // 일반 우선순위
    }
    
    /**
     * 계층별 설정
     */
    @Data
    public static class TierConfiguration {
        private int maxLatencyMs;
        private String[] channels;
        private TierPriority priority;
        private double samplingRate;
        private boolean async;
        private boolean batching;
    }
}