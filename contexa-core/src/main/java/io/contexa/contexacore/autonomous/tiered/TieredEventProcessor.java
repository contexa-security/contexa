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

    private final Map<EventTier, AtomicLong> tierCounters = new ConcurrentHashMap<>();
    
    public TieredEventProcessor() {
        for (EventTier tier : EventTier.values()) {
            tierCounters.put(tier, new AtomicLong(0));
        }
    }

    public EventTier determineTier(AuthenticationSuccessEvent event) {
        
        AuthenticationSuccessEvent.RiskLevel riskLevel = event.calculateRiskLevel();

        if (riskLevel == AuthenticationSuccessEvent.RiskLevel.CRITICAL ||
            riskLevel == AuthenticationSuccessEvent.RiskLevel.HIGH ||
            event.isAnomalyDetected()) {
            tierCounters.get(EventTier.CRITICAL).incrementAndGet();
            return EventTier.CRITICAL;
        }

        if (event.isMfaCompleted() ||
            riskLevel == AuthenticationSuccessEvent.RiskLevel.MEDIUM) {
            tierCounters.get(EventTier.CONTEXTUAL).incrementAndGet();
            return EventTier.CONTEXTUAL;
        }

        tierCounters.get(EventTier.GENERAL).incrementAndGet();
        return EventTier.GENERAL;
    }

    public EventTier determineTier(AuthenticationFailureEvent event) {
        
        if (event.determineAttackType() == AuthenticationFailureEvent.AttackType.BRUTE_FORCE ||
            event.determineAttackType() == AuthenticationFailureEvent.AttackType.CREDENTIAL_STUFFING ||
            event.determineAttackType() == AuthenticationFailureEvent.AttackType.SUSTAINED_ATTACK) {
            tierCounters.get(EventTier.CRITICAL).incrementAndGet();
            return EventTier.CRITICAL;
        }

        if (event.determineAttackType() == AuthenticationFailureEvent.AttackType.SUSPICIOUS ||
            event.getFailureCount() > 3) {
            tierCounters.get(EventTier.CONTEXTUAL).incrementAndGet();
            return EventTier.CONTEXTUAL;
        }

        tierCounters.get(EventTier.GENERAL).incrementAndGet();
        return EventTier.GENERAL;
    }

    public TierConfiguration getConfiguration(EventTier tier) {
        TierConfiguration config = new TierConfiguration();
        
        switch (tier) {
            case CRITICAL:
                config.setMaxLatencyMs(criticalMaxLatencyMs);
                config.setChannels(new String[]{"redis", "kafka"});
                config.setPriority(TierPriority.IMMEDIATE);
                config.setSamplingRate(1.0);  
                config.setAsync(false);  
                break;
                
            case CONTEXTUAL:
                config.setMaxLatencyMs(contextualMaxLatencyMs);
                config.setChannels(new String[]{"kafka", "redis"});
                config.setPriority(TierPriority.HIGH);
                config.setSamplingRate(1.0);  
                config.setAsync(true);  
                break;
                
            case GENERAL:
                config.setMaxLatencyMs(generalMaxLatencyMs);
                config.setChannels(new String[]{"kafka"});
                config.setPriority(TierPriority.NORMAL);
                config.setSamplingRate(generalSamplingRate);  
                config.setAsync(true);  
                config.setBatching(true);  
                break;
        }
        
        return config;
    }

    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new ConcurrentHashMap<>();
        
        for (Map.Entry<EventTier, AtomicLong> entry : tierCounters.entrySet()) {
            metrics.put(entry.getKey().name().toLowerCase() + "_count", entry.getValue().get());
        }

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

    public enum EventTier {
        CRITICAL,    
        CONTEXTUAL,  
        GENERAL      
    }

    public enum TierPriority {
        IMMEDIATE,   
        HIGH,        
        NORMAL       
    }

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