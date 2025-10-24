package io.contexa.contexaidentity.security.core.mfa.handler;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;

import java.io.IOException;

/**
 * 1차 인증 성공 후 또는 개별 MFA Factor 인증 성공 후
 * 다음 MFA 단계를 결정하고 실행하는 핸들러 인터페이스.
 */
public interface MfaContinuationHandler {

    /**
     * 1차 인증 성공 또는 이전 MFA Factor 인증 성공 후 호출됩니다.
     *
     * @param request        현재 요청
     * @param response       현재 응답
     * @param authentication 이전 단계의 성공한 Authentication 객체 (1차 인증 또는 이전 Factor 인증 결과)
     * @param factorContext  현재 MFA 세션 컨텍스트
     * @param flowConfig
     * @param o
     * @throws IOException
     * @throws ServletException
     */
    void
    continueMfaFlow(HttpServletRequest request,
                    HttpServletResponse response,
                    Authentication authentication, // 이전 단계 인증 결과
                    FactorContext factorContext,
                    AuthenticationFlowConfig flowConfig,
                    Object o) throws IOException, ServletException;
}
