package io.contexa.contexacore.autonomous.event;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Security Event Listener Interface
 * 
 * 보안 이벤트 리스너 인터페이스로 다양한 보안 이벤트를 처리합니다.
 */
public interface SecurityEventListener {

    // 인터페이스 정적 Logger
    Logger log = LoggerFactory.getLogger(SecurityEventListener.class);

    /**
     * 리스너 이름 가져오기
     */
    default String getListenerName() {
        return this.getClass().getSimpleName();
    }
    
    /**
     * 일반 보안 이벤트 처리
     */
    void onSecurityEvent(SecurityEvent event);
    
    /**
     * 배치 이벤트 처리
     */
    default void onBatchEvents(List<SecurityEvent> events) {
        log.debug("[SecurityEventListener] Processing batch events: count={}", events.size());
        for (SecurityEvent event : events) {
            onSecurityEvent(event);
        }
    }
    
    /**
     * AI Native: BLOCK action 이벤트 처리
     */
    default void onBlockEvent(SecurityEvent event, SecurityDecision decision) {
        if (decision != null && decision.getAction() == SecurityDecision.Action.BLOCK) {
            onSecurityEvent(event);
        }
    }

    /**
     * AI Native: CHALLENGE action 이벤트 처리
     */
    default void onChallengeEvent(SecurityEvent event, SecurityDecision decision) {
        if (decision != null && decision.getAction() == SecurityDecision.Action.CHALLENGE) {
            onSecurityEvent(event);
        }
    }

    /**
     * AI Native: action 기반 고위험 이벤트 처리
     */
    default void onHighRiskEventByAction(SecurityEvent event, SecurityDecision decision) {
        if (decision != null &&
            (decision.getAction() == SecurityDecision.Action.BLOCK ||
             decision.getAction() == SecurityDecision.Action.ESCALATE)) {
            onSecurityEvent(event);
        }
    }
    
    /**
     * 네트워크 이벤트 처리
     * AI Native v4.1.0: EventSource 필터링 제거 - 모든 이벤트 LLM 분석
     */
    default void onNetworkEvent(SecurityEvent event) {
        // AI Native v4.1.0: EventSource 필터링 제거 - 모든 이벤트 전달
        onSecurityEvent(event);
    }

    /**
     * 인증 이벤트 처리
     * AI Native v4.1.0: EventSource 필터링 제거 - 모든 이벤트 LLM 분석
     */
    default void onAuthenticationEvent(SecurityEvent event) {
        // AI Native v4.1.0: EventSource 필터링 제거 - 모든 이벤트 전달
        onSecurityEvent(event);
    }
    
    /**
     * 맬웨어 이벤트 처리 (AI Native: eventType 제거 - severity 기반 판단)
     * @deprecated eventType 필드 제거로 인해 사용 중단. onSecurityEvent() 사용 권장
     */
    @Deprecated(since = "4.0.0", forRemoval = true)
    default void onMalwareEvent(SecurityEvent event) {
        // AI Native: 모든 이벤트를 LLM이 분석하므로 무조건 전달
        onSecurityEvent(event);
    }

    /**
     * 이상 탐지 이벤트 처리 (AI Native: eventType 제거 - LLM 분석 기반)
     * @deprecated eventType 필드 제거로 인해 사용 중단. onSecurityEvent() 사용 권장
     */
    @Deprecated(since = "4.0.0", forRemoval = true)
    default void onAnomalyEvent(SecurityEvent event) {
        // AI Native: 모든 이벤트를 LLM이 분석하므로 무조건 전달
        onSecurityEvent(event);
    }

    /**
     * 정책 위반 이벤트 처리 (AI Native: eventType 제거 - LLM 분석 기반)
     * @deprecated eventType 필드 제거로 인해 사용 중단. onSecurityEvent() 사용 권장
     */
    @Deprecated(since = "4.0.0", forRemoval = true)
    default void onPolicyViolationEvent(SecurityEvent event) {
        // AI Native: 모든 이벤트를 LLM이 분석하므로 무조건 전달
        onSecurityEvent(event);
    }

    /**
     * 에러 처리
     */
    default void onError(SecurityEvent event, Exception e) {
        // 기본 에러 처리 - 로깅
        log.error("[SecurityEventListener] Error processing event {}: {}", event.getEventId(), e.getMessage(), e);
    }

    // AI Native v4.0.0: canHandle(EventType) 메서드 완전 제거
    // eventType 필드가 SecurityEvent에서 제거됨에 따라 삭제
    // 대체: canHandle(SecurityEvent.EventSource source) 사용
    
    /**
     * 이벤트 소스 처리 가능 여부
     */
    default boolean canHandle(SecurityEvent.EventSource source) {
        return true; // 기본적으로 모든 소스 처리
    }
    
    /**
     * 리스너 우선순위
     */
    default int getPriority() {
        return 100;
    }
    
    /**
     * 리스너 활성 여부
     */
    default boolean isActive() {
        return true;
    }
}