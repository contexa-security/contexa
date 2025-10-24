package io.contexa.contexaidentity.security.core.mfa.handler;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.enums.AuthType;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;

import java.io.IOException;

/**
 * MFA Factor 인증 실패 또는 전체 MFA 흐름 실패 시 호출되는 핸들러 인터페이스.
 */
public interface MfaFailureHandler {

    /**
     * 특정 MFA Factor 인증 시도 실패 시 호출됩니다.
     *
     * @param request 현재 요청
     * @param response 현재 응답
     * @param exception 발생한 인증 예외
     * @param failedFactorType 실패한 AuthType
     * @param factorContext 현재 MFA 세션 컨텍스트
     * @throws IOException
     * @throws ServletException
     */
    void onFactorFailure(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException exception,
                         AuthType failedFactorType,
                         FactorContext factorContext) throws IOException, ServletException;

    /**
     * 모든 MFA 시도가 최종적으로 실패했을 때 호출됩니다.
     *
     * @param request 현재 요청
     * @param response 현재 응답
     * @param exception 마지막으로 발생한 또는 종합적인 인증 예외
     * @param factorContext 현재 MFA 세션 컨텍스트
     * @throws IOException
     * @throws ServletException
     */
    void onGlobalMfaFailure(HttpServletRequest request,
                            HttpServletResponse response,
                            AuthenticationException exception,
                            FactorContext factorContext) throws IOException, ServletException;
}
