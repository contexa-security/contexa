package io.contexa.contexaidentity.security.statemachine.integration;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import jakarta.servlet.http.HttpServletRequest;

/**
 * State Machine Handler Advice 인터페이스
 * 핸들러 실행 전후로 State Machine과의 통합을 담당
 */
public interface StateMachineHandlerAdvice {

    /**
     * 핸들러 실행 전 처리
     * @return 핸들러 실행 가능 여부
     */
    boolean beforeHandler(String handlerName, FactorContext context,
                          HttpServletRequest request);

    /**
     * 핸들러 실행 후 처리
     */
    void afterHandler(String handlerName, FactorContext context,
                      HttpServletRequest request, Object result);

    /**
     * 핸들러 에러 처리
     */
    void onHandlerError(String handlerName, FactorContext context,
                        HttpServletRequest request, Exception error);
}