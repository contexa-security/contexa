package io.contexa.contexacore.autonomous.event;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthorizationDecisionEvent;
import io.contexa.contexacore.autonomous.event.domain.SecurityIncidentEvent;
import io.contexa.contexacore.autonomous.event.domain.ThreatDetectionEvent;
import io.contexa.contexacore.autonomous.event.domain.AuditEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthenticationSuccessEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthenticationFailureEvent;

/**
 * 보안 이벤트 발행을 위한 인터페이스
 * 
 * 모든 보안 관련 이벤트를 Kafka/Redis로 발행하는 통합 인터페이스입니다.
 * OODA 루프의 '관찰(Observe)' 단계를 완성하는 핵심 컴포넌트입니다.
 */
public interface SecurityEventPublisher {
    
    /**
     * 인가 결정 이벤트 발행
     * 
     * @param event 인가 결정 이벤트
     */
    void publishAuthorizationEvent(AuthorizationDecisionEvent event);
    
    /**
     * 보안 사고 이벤트 발행
     * 
     * @param event 보안 사고 이벤트
     */
    void publishSecurityIncident(SecurityIncidentEvent event);
    
    /**
     * 위협 탐지 이벤트 발행
     * 
     * @param event 위협 탐지 이벤트
     */
    void publishThreatDetection(ThreatDetectionEvent event);
    
    /**
     * 감사 이벤트 발행
     * 
     * @param event 감사 이벤트
     */
    void publishAuditEvent(AuditEvent event);
    
    /**
     * 인증 성공 이벤트 발행 (Zero Trust)
     * 
     * @param event 인증 성공 이벤트
     */
    void publishAuthenticationSuccess(AuthenticationSuccessEvent event);
    
    /**
     * 인증 실패 이벤트 발행
     * 
     * @param event 인증 실패 이벤트
     */
    void publishAuthenticationFailure(AuthenticationFailureEvent event);
    
    /**
     * 일반 보안 이벤트 발행
     * 
     * @param event 보안 이벤트
     */
    void publishSecurityEvent(SecurityEvent event);
}