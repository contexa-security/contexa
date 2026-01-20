package io.contexa.contexacore.autonomous.processor;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.extern.slf4j.Slf4j;

import jakarta.annotation.PostConstruct;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;


@Slf4j
public class EventDeduplicator implements EventProcessor<SecurityEvent> {

    
    private static final ThreadLocal<MessageDigest> MESSAGE_DIGEST = ThreadLocal.withInitial(() -> {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    });

    
    private final SecurityPlaneProperties securityPlaneProperties;

    
    private Cache<String, Long> deduplicationCache;

    
    private final AtomicLong totalEvents = new AtomicLong(0);
    private final AtomicLong duplicateEvents = new AtomicLong(0);

    
    public EventDeduplicator(SecurityPlaneProperties securityPlaneProperties) {
        this.securityPlaneProperties = securityPlaneProperties;
    }

    
    private SecurityPlaneProperties.DeduplicationSettings getSettings() {
        return securityPlaneProperties.getDeduplication();
    }

    @PostConstruct
    public void initialize() {
        
        this.deduplicationCache = Caffeine.newBuilder()
                .maximumSize(getSettings().getCacheSize())
                .expireAfterWrite(getSettings().getWindowMinutes(), TimeUnit.MINUTES)
                .recordStats()
                .build();

        log.info("EventDeduplicator initialized - window: {} minutes, cache size: {}, enabled: {}",
                getSettings().getWindowMinutes(), getSettings().getCacheSize(), getSettings().isEnabled());
    }
    
    
    @Override
    public SecurityEvent process(SecurityEvent event) {
        if (event == null) {
            return null;
        }
        
        totalEvents.incrementAndGet();

        
        if (!getSettings().isEnabled()) {
            return event;
        }
        
        
        if (isDuplicate(event)) {
            duplicateEvents.incrementAndGet();
            
            log.debug("Duplicate event detected and filtered: eventId={}, userId={}",
                     event.getEventId(), event.getUserId());
            return null; 
        }
        
        return event;
    }
    
    
    private boolean isDuplicate(SecurityEvent event) {
        
        if (event.getEventId() != null && !event.getEventId().isEmpty()) {
            String idKey = "id:" + event.getEventId();
            Long existingTimestamp = deduplicationCache.getIfPresent(idKey);
            
            if (existingTimestamp != null) {
                log.trace("Duplicate detected by event ID: {}", event.getEventId());
                return true;
            }
            
            
            deduplicationCache.put(idKey, System.currentTimeMillis());
        }
        
        
        
        
        String contentHash = calculateEventHash(event);
        if (contentHash != null) {
            String hashKey = "hash:" + contentHash;

            if (deduplicationCache.getIfPresent(hashKey) != null) {
                
                log.trace("Duplicate detected by content hash: {}", contentHash.substring(0, 8));
                return true;
            }

            
            deduplicationCache.put(hashKey, System.currentTimeMillis());
        }
        
        return false;
    }
    
    
    private String calculateEventHash(SecurityEvent event) {
        
        MessageDigest md = MESSAGE_DIGEST.get();
        md.reset();  

        
        StringBuilder sb = new StringBuilder();

        
        if (event.getSourceIp() != null) {
            sb.append(event.getSourceIp()).append("|");
        }

        
        if (event.getUserId() != null) {
            sb.append(event.getUserId()).append("|");
        }

        

        
        if (event.getSeverity() != null) {
            sb.append(event.getSeverity().name()).append("|");
        }

        
        if (event.getTimestamp() != null) {
            sb.append(event.getTimestamp().getYear())
              .append(event.getTimestamp().getMonthValue())
              .append(event.getTimestamp().getDayOfMonth())
              .append(event.getTimestamp().getHour())
              .append(event.getTimestamp().getMinute());
        }

        
        if (event.getMetadata() != null) {
            Object action = event.getMetadata().get("action");
            if (action != null) {
                sb.append("|").append(action);
            }

            Object resource = event.getMetadata().get("resource");
            if (resource != null) {
                sb.append("|").append(resource);
            }
        }

        byte[] hashBytes = md.digest(sb.toString().getBytes());
        return Base64.getEncoder().encodeToString(hashBytes);
    }
    
    
    public DeduplicationStats getStatistics() {
        return DeduplicationStats.builder()
                .totalEvents(totalEvents.get())
                .duplicateEvents(duplicateEvents.get())
                .duplicateRate(calculateDuplicateRate())
                .cacheSize(deduplicationCache.estimatedSize())
                .cacheStats(deduplicationCache.stats())
                .build();
    }
    
    
    private double calculateDuplicateRate() {
        long total = totalEvents.get();
        if (total == 0) {
            return 0.0;
        }
        return (double) duplicateEvents.get() / total * 100;
    }
    
    
    public void clearCache() {
        deduplicationCache.invalidateAll();
        deduplicationCache.cleanUp();
        log.info("Deduplication cache cleared");
    }
    
    
    @Override
    public int getPriority() {
        return 50;
    }
    
    
    @Override
    public String getName() {
        return "EventDeduplicator";
    }
    
    
    @Override
    public boolean isEnabled() {
        return getSettings().isEnabled();
    }
    
    
    @lombok.Data
    @lombok.Builder
    public static class DeduplicationStats {
        private long totalEvents;
        private long duplicateEvents;
        private double duplicateRate;
        private long cacheSize;
        private com.github.benmanes.caffeine.cache.stats.CacheStats cacheStats;
    }
}