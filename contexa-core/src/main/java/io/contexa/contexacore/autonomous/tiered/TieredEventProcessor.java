package io.contexa.contexacore.autonomous.tiered;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthenticationSuccessEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthenticationFailureEvent;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;

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
     * 인증 성공 이벤트 계층 결정 (AI Native v3.3.0)
     *
     * LLM이 설정한 riskLevel 필드 기반으로 분류
     * 점수 기반 계산 없음 - LLM 판단 사용
     */
    public EventTier determineTier(AuthenticationSuccessEvent event) {
        // AI Native: LLM이 설정한 riskLevel 기반 분류
        AuthenticationSuccessEvent.RiskLevel riskLevel = event.calculateRiskLevel();

        // 고위험 또는 이상 탐지 -> Critical
        if (riskLevel == AuthenticationSuccessEvent.RiskLevel.CRITICAL ||
            riskLevel == AuthenticationSuccessEvent.RiskLevel.HIGH ||
            event.isAnomalyDetected()) {
            tierCounters.get(EventTier.CRITICAL).incrementAndGet();
            return EventTier.CRITICAL;
        }

        // MFA 완료 또는 중간 위험 -> Contextual
        if (event.isMfaCompleted() ||
            riskLevel == AuthenticationSuccessEvent.RiskLevel.MEDIUM) {
            tierCounters.get(EventTier.CONTEXTUAL).incrementAndGet();
            return EventTier.CONTEXTUAL;
        }

        // 일반 로그인 (MINIMAL, LOW, UNKNOWN) -> General
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