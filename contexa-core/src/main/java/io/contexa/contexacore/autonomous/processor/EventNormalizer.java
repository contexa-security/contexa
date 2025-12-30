package io.contexa.contexacore.autonomous.processor;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

/**
 * 보안 이벤트 정규화 처리기
 * 
 * Strategy 패턴을 적용하여 다양한 소스의 이벤트를 통일된 형식으로 정규화합니다.
 *
 * @since 1.0
 * @author contexa
 */
@Slf4j
public class EventNormalizer implements EventProcessor<SecurityEvent> {
    
    /**
     * 이벤트 정규화 처리
     * 
     * 다양한 소스에서 수집된 이벤트를 표준 형식으로 변환합니다.
     * - 타임스탬프 정규화
     * - 이벤트 타입 검증
     * - Severity 레벨 표준화
     * - IP 주소 형식 정규화
     * - 필수 필드 검증 및 기본값 설정
     * 
     * @param event 정규화할 보안 이벤트
     * @return 정규화된 보안 이벤트
     */
    @Override
    public SecurityEvent process(SecurityEvent event) {
        if (event == null) {
            log.warn("Null event received for normalization");
            return null;
        }
        
        // 타임스탬프 정규화
        normalizeTimestamp(event);

        // AI Native: eventType 정규화 제거 - 행동 패턴 기반 분석으로 전환

        // Severity 정규화
        normalizeSeverity(event);

        // IP 주소 정규화
        normalizeIpAddress(event);

        // 이벤트 ID 검증
        normalizeEventId(event);

        // Source 정규화
        normalizeSource(event);

        // AI Native: eventType 제거 - severity, userId 기반 로깅
        log.trace("Event normalized: eventId={}, severity={}, userId={}",
                 event.getEventId(), event.getSeverity(), event.getUserId());
        
        return event;
    }
    
    /**
     * 타임스탬프 정규화
     * null인 경우 현재 시간으로 설정
     */
    private void normalizeTimestamp(SecurityEvent event) {
        if (event.getTimestamp() == null) {
            event.setTimestamp(LocalDateTime.now());
            log.trace("Timestamp normalized to current time for event: {}", event.getEventId());
        }
    }
    
    // AI Native: normalizeEventType 제거 - eventType 필드 삭제됨

    /**
     * Severity 레벨 정규화 (AI Native: eventType 제거)
     * null인 경우 INFO로 설정
     */
    private void normalizeSeverity(SecurityEvent event) {
        if (event.getSeverity() == null) {
            // AI Native: eventType 없이 기본 INFO 설정
            event.setSeverity(SecurityEvent.Severity.INFO);
            log.trace("Severity normalized to INFO for event: {}", event.getEventId());
        }
    }
    
    /**
     * IP 주소 정규화
     * X-Forwarded-For 헤더 처리 및 형식 표준화
     */
    private void normalizeIpAddress(SecurityEvent event) {
        String sourceIp = event.getSourceIp();
        if (sourceIp != null && sourceIp.contains(",")) {
            // X-Forwarded-For 헤더 처리: 첫 번째 IP만 추출
            String normalizedIp = sourceIp.split(",")[0].trim();
            event.setSourceIp(normalizedIp);
            log.trace("Source IP normalized from {} to {} for event: {}", 
                     sourceIp, normalizedIp, event.getEventId());
        }
        
        // IPv6 주소 정규화
        if (sourceIp != null && sourceIp.contains("::")) {
            event.setSourceIp(normalizeIpv6(sourceIp));
        }
    }
    
    /**
     * IPv6 주소 정규화
     */
    private String normalizeIpv6(String ipv6) {
        // 간단한 IPv6 정규화 (로컬 주소 처리)
        if ("::1".equals(ipv6) || "0:0:0:0:0:0:0:1".equals(ipv6)) {
            return "127.0.0.1"; // IPv4 로컬로 변환
        }
        return ipv6.toLowerCase();
    }
    
    /**
     * 이벤트 ID 정규화
     * null인 경우 UUID 생성
     */
    private void normalizeEventId(SecurityEvent event) {
        if (event.getEventId() == null || event.getEventId().isEmpty()) {
            String newEventId = java.util.UUID.randomUUID().toString();
            event.setEventId(newEventId);
            log.debug("Event ID generated: {}", newEventId);
        }
    }
    
    /**
     * 이벤트 소스 정규화
     * null인 경우 UNKNOWN으로 설정
     */
    private void normalizeSource(SecurityEvent event) {
        if (event.getSource() == null) {
            event.setSource(SecurityEvent.EventSource.UNKNOWN);
            log.trace("Event source normalized to UNKNOWN for event: {}", event.getEventId());
        }
    }
    
    /**
     * 프로세서 우선순위
     * 정규화는 가장 먼저 수행되어야 하므로 높은 우선순위
     */
    @Override
    public int getPriority() {
        return 100;
    }
    
    /**
     * 프로세서 이름
     */
    @Override
    public String getName() {
        return "EventNormalizer";
    }
    
    /**
     * 프로세서 활성 상태
     */
    @Override
    public boolean isEnabled() {
        return true;
    }
}