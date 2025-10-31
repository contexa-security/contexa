package io.contexa.contexaidentity.security.exceptionhandling;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaidentity.domain.ErrorResponse;
import io.contexa.contexaidentity.security.enums.ErrorCode;
import io.contexa.contexaidentity.security.utils.WebUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.util.Assert;

import java.io.IOException;
import java.time.Instant;

/**
 * MFA Authentication Entry Point
 *
 * Spring Security의 LoginUrlAuthenticationEntryPoint를 상속하여 MFA 전용 기능을 추가한 EntryPoint.
 * 인증되지 않은 사용자의 접근 시 적절한 로그인 페이지로 리다이렉트하거나 JSON 에러 응답을 반환합니다.
 *
 * 주요 기능:
 * 1. HTML 요청 → DSL 설정된 loginPage로 리다이렉트 또는 forward (부모 클래스 기능)
 * 2. API/AJAX 요청 → JSON 형식 에러 응답 반환 (MFA 전용 확장)
 * 3. DSL 설정(AuthenticationFlowConfig)에서 자동 생성됨
 * 4. HTTPS 강제 전환 지원 (forceHttps - 부모 클래스 기능)
 * 5. Forward/Redirect 선택 가능 (useForward - 부모 클래스 기능)
 * 6. PortMapper 지원 (부모 클래스 기능)
 *
 * 상속 구조:
 * - LoginUrlAuthenticationEntryPoint (부모)
 *   - forceHttps, useForward, PortMapper, buildRedirectUrlToLoginPage() 등 제공
 * - MfaAuthenticationEntryPoint (자식)
 *   - API/AJAX 요청 시 JSON 에러 응답 추가
 *
 * 사용 예시:
 * <pre>
 * // MfaDslConfigurerImpl에서 자동 생성
 * String loginPageUrl = primaryAuth.getLoginPage();  // "/loginForm" 또는 커스텀 페이지
 * MfaAuthenticationEntryPoint entryPoint = new MfaAuthenticationEntryPoint(objectMapper, loginPageUrl);
 *
 * // 선택적 설정 (부모 클래스 메서드)
 * entryPoint.setUseForward(true);      // forward 사용 (기본: false, redirect)
 * entryPoint.setForceHttps(true);      // HTTPS 강제 전환 (기본: false)
 * entryPoint.setPortMapper(portMapper); // 커스텀 PortMapper 설정
 *
 * // HttpSecurity에 기본 EntryPoint로 등록
 * exceptionHandling.defaultAuthenticationEntryPointFor(entryPoint, matcher);
 * </pre>
 *
 * @see org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
 * @see io.contexa.contexaidentity.security.core.dsl.configurer.impl.MfaDslConfigurerImpl
 */
public class MfaAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    /**
     * Constructor
     *
     * @param objectMapper JSON 직렬화를 위한 ObjectMapper
     * @param loginPageUrl 로그인 페이지 URL (DSL 설정값 또는 기본값)
     * @throws IllegalArgumentException objectMapper가 null이거나 loginPageUrl이 유효하지 않은 경우
     */
    public MfaAuthenticationEntryPoint(ObjectMapper objectMapper, String loginPageUrl) {
        super(loginPageUrl);  // ⭐ 부모 클래스 생성자 호출
        Assert.notNull(objectMapper, "ObjectMapper cannot be null");
        this.objectMapper = objectMapper;
    }

    /**
     * 인증 진입점 처리
     *
     * API/AJAX 요청이면 JSON 에러 응답을 반환하고,
     * 그 외의 HTML 요청이면 부모 클래스의 로직(redirect 또는 forward)을 사용합니다.
     *
     * @param request 요청
     * @param response 응답
     * @param authException 인증 예외
     * @throws IOException I/O 예외
     * @throws ServletException Servlet 예외
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {

        // MFA 확장 기능: API/AJAX 요청 → JSON 에러 응답
        if (WebUtil.isApiOrAjaxRequest(request)) {
            response.setContentType("application/json; charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            ErrorResponse body = new ErrorResponse(
                    Instant.now().toString(),
                    HttpServletResponse.SC_UNAUTHORIZED,
                    ErrorCode.AUTH_FAILED.code(),
                    ErrorCode.AUTH_FAILED.message(),
                    request.getRequestURI()
            );

            objectMapper.writeValue(response.getOutputStream(), body);
            return;
        }

        // HTML 요청 → 부모 클래스의 redirect/forward 로직 사용
        // (forceHttps, useForward, PortMapper 등 자동 적용)
        super.commence(request, response, authException);
    }
}
