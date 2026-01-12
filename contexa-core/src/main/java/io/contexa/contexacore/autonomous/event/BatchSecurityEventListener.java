package io.contexa.contexacore.autonomous.event;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

import java.util.List;

/**
 * 배치 보안 이벤트 리스너 인터페이스
 *
 * AI Native v5.0.0: Kafka Batch Listener 지원
 * - 배치 이벤트 처리에 특화된 인터페이스
 * - SecurityEventListener를 확장하여 배치 처리 지원
 */
public interface BatchSecurityEventListener extends SecurityEventListener {

    /**
     * 배치 이벤트 처리 (필수 구현)
     * Kafka Batch Listener에서 수신한 이벤트 배치를 처리
     *
     * @param events 처리할 이벤트 배치 (최대 10개, 설정 가능)
     */
    @Override
    void onBatchEvents(List<SecurityEvent> events);

    /**
     * 단일 이벤트 처리 (기본 구현: 배치로 래핑)
     * 배치 처리 리스너에서 단일 이벤트는 배치로 래핑하여 처리
     */
    @Override
    default void onSecurityEvent(SecurityEvent event) {
        onBatchEvents(List.of(event));
    }
}
