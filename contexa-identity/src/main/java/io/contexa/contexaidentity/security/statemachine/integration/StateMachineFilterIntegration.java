package io.contexa.contexaidentity.security.statemachine.integration;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * State Machine과 Filter 통합 인터페이스
 */
public interface StateMachineFilterIntegration {

    /**
     * 필터 처리 전 State Machine 상태 확인 및 초기화
     * @return 계속 진행 여부
     */
    boolean preProcess(HttpServletRequest request, HttpServletResponse response,
                       FactorContext context);

    /**
     * 필터 처리 후 State Machine 이벤트 전송
     */
    void postProcess(HttpServletRequest request, HttpServletResponse response,
                     FactorContext context, Object result);

    /**
     * 현재 상태에서 요청 처리를 진행할 수 있는지 확인
     */
    boolean canProceed(HttpServletRequest request, FactorContext context);
}