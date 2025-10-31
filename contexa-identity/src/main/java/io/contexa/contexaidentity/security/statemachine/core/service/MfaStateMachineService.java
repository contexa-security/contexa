package io.contexa.contexaidentity.security.statemachine.core.service;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import jakarta.servlet.http.HttpServletRequest;

import java.util.Map;

/**
 * 완전 일원화된 MFA State Machine 서비스 인터페이스
 * - State Machine이 유일한 상태 저장소 역할
 * - ContextPersistence 완전 대체
 */
public interface MfaStateMachineService {

    /**
     * State Machine 초기화 및 FactorContext 저장
     * @param context 초기 FactorContext
     * @param request HTTP 요청
     */
    void initializeStateMachine(FactorContext context, HttpServletRequest request);

    /**
     * 이벤트 전송 및 상태 변경
     * @param event MFA 이벤트
     * @param context 현재 FactorContext
     * @param request HTTP 요청
     * @return 이벤트 수락 여부
     */
    boolean sendEvent(MfaEvent event, FactorContext context, HttpServletRequest request);

    /**
     * Phase 2: 추가 헤더와 함께 이벤트 전송
     * @param event MFA 이벤트
     * @param context 현재 FactorContext
     * @param request HTTP 요청
     * @param additionalHeaders 추가 헤더 (예: mfaDecision)
     * @return 이벤트 수락 여부
     */
    boolean sendEvent(MfaEvent event, FactorContext context, HttpServletRequest request, Map<String, Object> additionalHeaders);

    /**
     * FactorContext 조회 - State Machine에서만 조회
     * @param sessionId MFA 세션 ID
     * @return FactorContext 또는 null
     */
    FactorContext getFactorContext(String sessionId);

    /**
     * FactorContext 저장 - State Machine에만 저장
     * @param context 저장할 FactorContext
     */
    void saveFactorContext(FactorContext context);

    /**
     * 현재 상태 조회
     * @param sessionId MFA 세션 ID
     * @return 현재 MFA 상태
     */
    MfaState getCurrentState(String sessionId);

    /**
     * 상태만 업데이트 (성능 최적화용)
     * @param sessionId MFA 세션 ID
     * @param newState 새로운 상태
     * @return 업데이트 성공 여부
     */
    boolean updateStateOnly(String sessionId, MfaState newState);

    /**
     * State Machine 해제 및 정리
     * @param sessionId MFA 세션 ID
     */
    void releaseStateMachine(String sessionId);
}