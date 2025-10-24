package io.contexa.contexaiam.common.event.dto;

import java.time.LocalDateTime;
/** [신규] 모든 도메인 이벤트의 기반이 되는 추상 클래스 */
public abstract class DomainEvent {
    private final LocalDateTime occurredOn = LocalDateTime.now();
    public LocalDateTime getOccurredOn() { return occurredOn; }
}