package io.contexa.contexacore.autonomous.event;

import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;

/**
 * 보안 이벤트 발행을 위한 인터페이스
 *
 * AI Native v14.0: ZeroTrustSpringEvent로 통일
 *
 * 모든 보안 관련 이벤트를 Kafka로 발행하는 통합 인터페이스입니다.
 * - 인가 이벤트: category=AUTHORIZATION
 * - 인증 성공 이벤트: category=AUTHENTICATION, eventType=SUCCESS
 * - 인증 실패 이벤트: category=AUTHENTICATION, eventType=FAILURE
 *
 * OODA 루프의 '관찰(Observe)' 단계를 완성하는 핵심 컴포넌트입니다.
 */
public interface SecurityEventPublisher {

    /**
     * Zero Trust 공통 이벤트 발행
     *
     * AI Native v14.0: 모든 보안 이벤트는 이 메서드로 통일
     *
     * @param event ZeroTrustSpringEvent 공통 이벤트
     */
    void publishGenericSecurityEvent(ZeroTrustSpringEvent event);
}
