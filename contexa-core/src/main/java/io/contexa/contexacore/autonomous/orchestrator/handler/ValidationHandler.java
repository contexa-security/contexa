package io.contexa.contexacore.autonomous.orchestrator.handler;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.orchestrator.SecurityEventHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 보안 이벤트 유효성 검증 핸들러
 *
 * SecurityPlaneAgent.processSecurityEvent()의 초반 검증 로직을 분리
 * - 중복 이벤트 필터링
 * - 이벤트 유효성 검증
 * - 필수 필드 확인
 *
 * @author AI3Security
 * @since 1.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ValidationHandler implements SecurityEventHandler {

    // 처리된 이벤트 캐시 (중복 방지용)
    private final Map<String, Long> processedEventCache = new ConcurrentHashMap<>();

    // 캐시 만료 시간 (24시간)
    private static final long CACHE_EXPIRY_MS = 24 * 60 * 60 * 1000;

    @Override
    public boolean handle(SecurityEventContext context) {
        SecurityEvent event = context.getSecurityEvent();

        if (event == null) {
            log.info("[ValidationHandler] Null security event in context");
            context.markAsFailed("Null security event");
            return false;
        }

        String eventId = event.getEventId();
        log.debug("[ValidationHandler] Validating event: {}", eventId);

        // 1. 중복 이벤트 체크
        if (isDuplicateEvent(eventId)) {
            log.debug("[ValidationHandler] Duplicate event detected and skipped: {}", eventId);
            context.updateProcessingStatus(SecurityEventContext.ProcessingStatus.SKIPPED);
            context.addMetadata("skippedReason", "Duplicate event");
            return false; // 처리 중단
        }

        // 2. 필수 필드 검증
        if (!validateRequiredFields(event)) {
            log.warn("[ValidationHandler] Invalid event - missing required fields: {}", eventId);
            context.markAsFailed("Missing required fields");
            return false;
        }

        // 3. 이벤트 시간 검증 (너무 오래된 이벤트 필터링)
        if (!validateEventTime(event)) {
            log.warn("[ValidationHandler] Event too old: {}", eventId);
            context.updateProcessingStatus(SecurityEventContext.ProcessingStatus.SKIPPED);
            context.addMetadata("skippedReason", "Event too old");
            return false;
        }

        // 4. 캐시에 추가
        markEventAsProcessed(eventId);

        // 5. 검증 완료 메타데이터 추가
        context.updateProcessingStatus(SecurityEventContext.ProcessingStatus.ANALYZING);
        context.addMetadata("validationPassed", true);
        context.addMetadata("validatedAt", System.currentTimeMillis());

        log.debug("[ValidationHandler] Event {} passed validation", eventId);
        return true; // 다음 핸들러로 진행
    }

    /**
     * 중복 이벤트 확인
     */
    private boolean isDuplicateEvent(String eventId) {
        // 캐시 정리 (오래된 항목 제거)
        cleanExpiredCache();

        return processedEventCache.containsKey(eventId);
    }

    /**
     * 이벤트를 처리됨으로 표시
     */
    private void markEventAsProcessed(String eventId) {
        processedEventCache.put(eventId, System.currentTimeMillis());
    }

    /**
     * 필수 필드 검증
     */
    private boolean validateRequiredFields(SecurityEvent event) {
        // EventId는 필수
        if (event.getEventId() == null || event.getEventId().isEmpty()) {
            return false;
        }

        // EventType은 필수
        if (event.getEventType() == null) {
            return false;
        }

        // Timestamp는 필수
        if (event.getTimestamp() == null) {
            return false;
        }

        return true;
    }

    /**
     * 이벤트 시간 검증 (24시간 이내 이벤트만 처리)
     */
    private boolean validateEventTime(SecurityEvent event) {
        if (event.getTimestamp() == null) {
            return false;
        }

        long eventTime = event.getTimestamp().atZone(java.time.ZoneId.systemDefault()).toInstant().toEpochMilli();
        long currentTime = System.currentTimeMillis();
        long age = currentTime - eventTime;

        // 24시간보다 오래된 이벤트는 무시
        return age <= CACHE_EXPIRY_MS;
    }

    /**
     * 만료된 캐시 항목 제거
     */
    private void cleanExpiredCache() {
        long currentTime = System.currentTimeMillis();
        processedEventCache.entrySet().removeIf(entry ->
            currentTime - entry.getValue() > CACHE_EXPIRY_MS
        );
    }

    @Override
    public String getName() {
        return "ValidationHandler";
    }

    @Override
    public int getOrder() {
        return 10; // 가장 먼저 실행
    }
}