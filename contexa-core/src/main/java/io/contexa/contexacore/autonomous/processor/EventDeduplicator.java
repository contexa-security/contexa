package io.contexa.contexacore.autonomous.processor;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 보안 이벤트 중복 제거 처리기
 * 
 * Strategy 패턴을 적용하여 중복 이벤트를 효과적으로 필터링합니다.
 * Caffeine 캐시를 사용하여 고성능 중복 검사를 수행합니다.
 * 
 * @since 1.0
 * @author AI3Security
 */
@Slf4j
@Component
public class EventDeduplicator implements EventProcessor<SecurityEvent> {
    
    @Value("${security.deduplication.window-minutes:5}")
    private int deduplicationWindowMinutes;
    
    @Value("${security.deduplication.cache-size:10000}")
    private int cacheSize;
    
    @Value("${security.deduplication.enabled:true}")
    private boolean deduplicationEnabled;
    
    // Caffeine 캐시를 사용한 고성능 중복 검사
    private Cache<String, Long> deduplicationCache;
    
    // 통계
    private final AtomicLong totalEvents = new AtomicLong(0);
    private final AtomicLong duplicateEvents = new AtomicLong(0);
    
    @PostConstruct
    public void initialize() {
        // Caffeine 캐시 초기화
        this.deduplicationCache = Caffeine.newBuilder()
                .maximumSize(cacheSize)
                .expireAfterWrite(deduplicationWindowMinutes, TimeUnit.MINUTES)
                .recordStats()
                .build();
        
        log.info("EventDeduplicator initialized - window: {} minutes, cache size: {}, enabled: {}",
                deduplicationWindowMinutes, cacheSize, deduplicationEnabled);
    }
    
    /**
     * 이벤트 중복 제거 처리
     * 
     * 설정된 시간 윈도우 내에서 중복 이벤트를 필터링합니다.
     * 이벤트 ID와 내용 해시를 기반으로 중복을 판단합니다.
     * 
     * @param event 검사할 보안 이벤트
     * @return 중복이 아닌 경우 이벤트 반환, 중복인 경우 null
     */
    @Override
    public SecurityEvent process(SecurityEvent event) {
        if (event == null) {
            return null;
        }
        
        totalEvents.incrementAndGet();
        
        // 중복 제거 비활성화 시 통과
        if (!deduplicationEnabled) {
            return event;
        }
        
        // 중복 검사
        if (isDuplicate(event)) {
            duplicateEvents.incrementAndGet();
            log.debug("Duplicate event detected and filtered: eventId={}, type={}", 
                     event.getEventId(), event.getEventType());
            return null; // 중복 이벤트 필터링
        }
        
        return event;
    }
    
    /**
     * 이벤트 중복 여부 확인
     * 
     * 1. 이벤트 ID 기반 중복 검사
     * 2. 이벤트 내용 해시 기반 중복 검사
     */
    private boolean isDuplicate(SecurityEvent event) {
        // 1. 이벤트 ID로 중복 검사
        if (event.getEventId() != null && !event.getEventId().isEmpty()) {
            String idKey = "id:" + event.getEventId();
            Long existingTimestamp = deduplicationCache.getIfPresent(idKey);
            
            if (existingTimestamp != null) {
                log.trace("Duplicate detected by event ID: {}", event.getEventId());
                return true;
            }
            
            // 캐시에 추가
            deduplicationCache.put(idKey, System.currentTimeMillis());
        }
        
        // 2. 이벤트 내용 해시로 중복 검사
        String contentHash = calculateEventHash(event);
        if (contentHash != null) {
            String hashKey = "hash:" + contentHash;
            Long existingTimestamp = deduplicationCache.getIfPresent(hashKey);
            
            if (existingTimestamp != null) {
                // 같은 내용의 이벤트가 짧은 시간 내에 반복
                long timeDiff = System.currentTimeMillis() - existingTimestamp;
                if (timeDiff < TimeUnit.MINUTES.toMillis(deduplicationWindowMinutes)) {
                    log.trace("Duplicate detected by content hash: {} ({}ms apart)", 
                             contentHash.substring(0, 8), timeDiff);
                    return true;
                }
            }
            
            // 캐시에 추가
            deduplicationCache.put(hashKey, System.currentTimeMillis());
        }
        
        return false;
    }
    
    /**
     * 이벤트 내용 기반 해시 계산
     * 
     * 주요 필드를 조합하여 이벤트의 고유 해시를 생성합니다.
     * 시간은 분 단위로만 포함하여 미세한 시간 차이는 무시합니다.
     */
    private String calculateEventHash(SecurityEvent event) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            
            // 주요 필드를 기반으로 해시 생성
            StringBuilder sb = new StringBuilder();
            
            // 이벤트 타입
            if (event.getEventType() != null) {
                sb.append(event.getEventType().name()).append("|");
            }
            
            // 소스 IP
            if (event.getSourceIp() != null) {
                sb.append(event.getSourceIp()).append("|");
            }
            
            // 사용자 ID
            if (event.getUserId() != null) {
                sb.append(event.getUserId()).append("|");
            }
            
            // 타겟 IP
            if (event.getTargetIp() != null) {
                sb.append(event.getTargetIp()).append("|");
            }
            
            // Severity
            if (event.getSeverity() != null) {
                sb.append(event.getSeverity().name()).append("|");
            }
            
            // 시간은 분 단위로만 포함 (초 단위 반복 방지)
            if (event.getTimestamp() != null) {
                sb.append(event.getTimestamp().getYear())
                  .append(event.getTimestamp().getMonthValue())
                  .append(event.getTimestamp().getDayOfMonth())
                  .append(event.getTimestamp().getHour())
                  .append(event.getTimestamp().getMinute());
            }
            
            // 주요 메타데이터 필드
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
            
        } catch (NoSuchAlgorithmException e) {
            log.error("Failed to calculate event hash", e);
            return null;
        }
    }
    
    /**
     * 중복 제거 통계 조회
     */
    public DeduplicationStats getStatistics() {
        return DeduplicationStats.builder()
                .totalEvents(totalEvents.get())
                .duplicateEvents(duplicateEvents.get())
                .duplicateRate(calculateDuplicateRate())
                .cacheSize(deduplicationCache.estimatedSize())
                .cacheStats(deduplicationCache.stats())
                .build();
    }
    
    /**
     * 중복률 계산
     */
    private double calculateDuplicateRate() {
        long total = totalEvents.get();
        if (total == 0) {
            return 0.0;
        }
        return (double) duplicateEvents.get() / total * 100;
    }
    
    /**
     * 캐시 초기화
     */
    public void clearCache() {
        deduplicationCache.invalidateAll();
        deduplicationCache.cleanUp();
        log.info("Deduplication cache cleared");
    }
    
    /**
     * 프로세서 우선순위
     * 정규화 다음에 수행되어야 하므로 중간 우선순위
     */
    @Override
    public int getPriority() {
        return 50;
    }
    
    /**
     * 프로세서 이름
     */
    @Override
    public String getName() {
        return "EventDeduplicator";
    }
    
    /**
     * 프로세서 활성 상태
     */
    @Override
    public boolean isEnabled() {
        return deduplicationEnabled;
    }
    
    /**
     * 중복 제거 통계 DTO
     */
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