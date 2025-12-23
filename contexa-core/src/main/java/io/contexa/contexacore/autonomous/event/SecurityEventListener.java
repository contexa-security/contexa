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
     * 고위험 이벤트 처리
     *
     * AI Native v3.3.0: severity 기반 판단 (하위 호환)
     * onBlockEvent() 사용 권장
     *
     * @deprecated AI Native 원칙 위반 - onBlockEvent() 사용 권장
     */
    @Deprecated(since = "3.1.0", forRemoval = true)
    default void onHighRiskEvent(SecurityEvent event) {
        // AI Native: severity 기반 판단 (하위 호환)
        if (event.getSeverity() == SecurityEvent.Severity.CRITICAL ||
            event.getSeverity() == SecurityEvent.Severity.HIGH) {
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
     */
    default void onNetworkEvent(SecurityEvent event) {
        if (event.isNetworkRelated()) {
            onSecurityEvent(event);
        }
    }
    
    /**
     * 인증 이벤트 처리
     */
    default void onAuthenticationEvent(SecurityEvent event) {
        if (event.isAuthenticationRelated()) {
            onSecurityEvent(event);
        }
    }
    
    /**
     * 맬웨어 이벤트 처리
     */
    default void onMalwareEvent(SecurityEvent event) {
        if (event.getEventType() == SecurityEvent.EventType.MALWARE_DETECTED) {
            onSecurityEvent(event);
        }
    }
    
    /**
     * 이상 탐지 이벤트 처리
     */
    default void onAnomalyEvent(SecurityEvent event) {
        if (event.getEventType() == SecurityEvent.EventType.ANOMALY_DETECTED) {
            onSecurityEvent(event);
        }
    }
    
    /**
     * 정책 위반 이벤트 처리
     */
    default void onPolicyViolationEvent(SecurityEvent event) {
        if (event.getEventType() == SecurityEvent.EventType.POLICY_VIOLATION) {
            onSecurityEvent(event);
        }
    }
    
    /**
     * 에러 처리
     */
    default void onError(SecurityEvent event, Exception e) {
        // 기본 에러 처리 - 로깅
        log.error("[SecurityEventListener] Error processing event {}: {}", event.getEventId(), e.getMessage(), e);
    }
    
    /**
     * 이벤트 타입 처리 가능 여부
     */
    default boolean canHandle(SecurityEvent.EventType eventType) {
        return true; // 기본적으로 모든 타입 처리
    }
    
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