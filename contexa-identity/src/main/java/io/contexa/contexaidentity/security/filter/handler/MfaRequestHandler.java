package io.contexa.contexaidentity.security.filter.handler;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.matcher.MfaRequestType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * MFA 요청 처리 핸들러 인터페이스
 * - 다양한 MFA 요청 타입 처리를 위한 통합 인터페이스
 * - State Machine 기반 구현체들이 이 인터페이스를 구현
 */
public interface MfaRequestHandler {

    /**
     * MFA 요청 처리
     * @param requestType MFA 요청 타입
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @param context FactorContext
     * @param filterChain 필터 체인
     */
    void handleRequest(MfaRequestType requestType, HttpServletRequest request,
                       HttpServletResponse response, FactorContext context,
                       FilterChain filterChain) throws ServletException, IOException;

    /**
     * 터미널 상태 컨텍스트 처리
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @param context FactorContext
     */
    void handleTerminalContext(HttpServletRequest request, HttpServletResponse response,
                               FactorContext context) throws ServletException, IOException;

    /**
     * 일반적인 에러 처리
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @param context FactorContext (null 가능)
     * @param error 발생한 예외
     */
    void handleGenericError(HttpServletRequest request, HttpServletResponse response,
                            FactorContext context, Exception error) throws ServletException, IOException;
}