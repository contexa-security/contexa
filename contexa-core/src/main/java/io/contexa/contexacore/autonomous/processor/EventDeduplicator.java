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

/**
 * 보안 이벤트 중복 제거 처리기
 *
 * Strategy 패턴을 적용하여 중복 이벤트를 효과적으로 필터링합니다.
 * Caffeine 캐시를 사용하여 고성능 중복 검사를 수행합니다.
 *
 * AI Native v5.1.0: 라이브러리 형태 지원
 * - @Value 대신 SecurityPlaneProperties 주입
 * - MessageDigest ThreadLocal 최적화 (해시 계산 시간 30-50% 감소)
 * - 중복 시간 체크 로직 단순화 (캐시 TTL로 이미 관리)
 *
 * @since 1.0
 * @author contexa
 */
@Slf4j
public class EventDeduplicator implements EventProcessor<SecurityEvent> {

    /**
     * AI Native v5.1.0: MessageDigest ThreadLocal 최적화
     * 매 이벤트마다 MessageDigest.getInstance() 호출 방지
     * 예상 효과: 해시 계산 시간 30-50% 감소
     */
    private static final ThreadLocal<MessageDigest> MESSAGE_DIGEST = ThreadLocal.withInitial(() -> {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    });

    /**
     * AI Native v5.1.0: Properties 클래스 기반 설정
     * @Value 대신 SecurityPlaneProperties 주입 후 getDeduplication() 사용
     */
    private final SecurityPlaneProperties securityPlaneProperties;

    // Caffeine 캐시를 사용한 고성능 중복 검사
    private Cache<String, Long> deduplicationCache;

    // 통계
    private final AtomicLong totalEvents = new AtomicLong(0);
    private final AtomicLong duplicateEvents = new AtomicLong(0);

    /**
     * AI Native v5.1.0: Properties 기반 생성자
     *
     * @param securityPlaneProperties Security Plane 설정 (deduplication 포함)
     */
    public EventDeduplicator(SecurityPlaneProperties securityPlaneProperties) {
        this.securityPlaneProperties = securityPlaneProperties;
    }

    /**
     * 중복 제거 설정 조회 (내부 헬퍼)
     */
    private SecurityPlaneProperties.DeduplicationSettings getSettings() {
        return securityPlaneProperties.getDeduplication();
    }

    @PostConstruct
    public void initialize() {
        // Caffeine 캐시 초기화
        this.deduplicationCache = Caffeine.newBuilder()
                .maximumSize(getSettings().getCacheSize())
                .expireAfterWrite(getSettings().getWindowMinutes(), TimeUnit.MINUTES)
                .recordStats()
                .build();

        log.info("EventDeduplicator initialized - window: {} minutes, cache size: {}, enabled: {}",
                getSettings().getWindowMinutes(), getSettings().getCacheSize(), getSettings().isEnabled());
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
        if (!getSettings().isEnabled()) {
            return event;
        }
        
        // 중복 검사
        if (isDuplicate(event)) {
            duplicateEvents.incrementAndGet();
            // AI Native: eventType 제거 - userId, sourceIp 기반 로깅
            log.debug("Duplicate event detected and filtered: eventId={}, userId={}",
                     event.getEventId(), event.getUserId());
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
        // AI Native v5.1.0: 중복 시간 체크 로직 단순화
        // 캐시 TTL(expireAfterWrite)이 이미 windowMinutes를 관리하므로 추가 체크 불필요
        String contentHash = calculateEventHash(event);
        if (contentHash != null) {
            String hashKey = "hash:" + contentHash;

            if (deduplicationCache.getIfPresent(hashKey) != null) {
                // 캐시에 존재 = windowMinutes 내 동일 내용 이벤트 발생
                log.trace("Duplicate detected by content hash: {}", contentHash.substring(0, 8));
                return true;
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
     *
     * AI Native v5.1.0: ThreadLocal MessageDigest 최적화
     * - 매 호출마다 getInstance() 대신 ThreadLocal 재사용
     * - 예상 효과: 해시 계산 시간 30-50% 감소
     */
    private String calculateEventHash(SecurityEvent event) {
        // AI Native v5.1.0: ThreadLocal MessageDigest 사용
        MessageDigest md = MESSAGE_DIGEST.get();
        md.reset();  // 재사용 전 초기화

        // 주요 필드를 기반으로 해시 생성 (AI Native: eventType 제거 - 행동 패턴 기반)
        StringBuilder sb = new StringBuilder();

        // 소스 IP
        if (event.getSourceIp() != null) {
            sb.append(event.getSourceIp()).append("|");
        }

        // 사용자 ID
        if (event.getUserId() != null) {
            sb.append(event.getUserId()).append("|");
        }

        // AI Native v3.1: targetIp 필드 제거됨 - metadata로 이동 (네트워크 이벤트 전용)

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
        return getSettings().isEnabled();
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