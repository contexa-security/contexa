package io.contexa.contexaidentity.security.handler;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.Nullable;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;
import java.util.Map;

/**
 * 플랫폼 인증 실패 처리 확장 인터페이스
 *
 * 사용자가 이 인터페이스를 구현하여 커스텀 실패 처리 로직을 추가할 수 있습니다.
 * 플랫폼의 핵심 실패 처리 로직 이후에 호출됩니다.
 */
public interface PlatformAuthenticationFailureHandler extends AuthenticationFailureHandler {

    /**
     * 플랫폼 실패 처리 이후 호출되는 확장 메서드
     *
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @param exception 인증 예외
     * @param factorContext MFA 컨텍스트 (MFA 실패인 경우, null일 수 있음)
     * @param failureType 실패 유형 (PRIMARY_AUTH, MFA_FACTOR 등)
     * @param errorDetails 플랫폼이 준비한 에러 상세 정보
     * @throws IOException IO 예외
     * @throws ServletException 서블릿 예외
     */
    default void onAuthenticationFailure(HttpServletRequest request,
                                 HttpServletResponse response,
                                 AuthenticationException exception,
                                 @Nullable FactorContext factorContext,
                                 FailureType failureType,
                                 Map<String, Object> errorDetails) throws IOException, ServletException {

    }

    // 기존 onAuthenticationFailure 메서드는 default로 구현
    @Override
    default void onAuthenticationFailure(HttpServletRequest request,
                                         HttpServletResponse response,
                                         AuthenticationException exception) throws IOException, ServletException {
        // 플랫폼이 직접 호출하므로 여기서는 아무것도 하지 않음
    }

    /**
     * 인증 실패 유형
     */
    enum FailureType {
        PRIMARY_AUTH_FAILED,        // 1차 인증 실패
        MFA_FACTOR_FAILED,         // MFA 팩터 검증 실패
        MFA_MAX_ATTEMPTS_EXCEEDED, // MFA 최대 시도 횟수 초과
        MFA_SESSION_NOT_FOUND,     // MFA 세션 미발견
        MFA_GLOBAL_FAILURE         // MFA 전역 실패
    }
}