package io.contexa.contexaidentity.security.exceptionhandling;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaidentity.domain.ErrorResponse;
import io.contexa.contexaidentity.security.enums.ErrorCode;
import io.contexa.contexaidentity.security.utils.WebUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.Assert;

import java.io.IOException;
import java.time.Instant;

/**
 * MFA Authentication Entry Point
 *
 * Spring Security의 LoginUrlAuthenticationEntryPoint 패턴을 따르는 MFA 전용 EntryPoint.
 * 인증되지 않은 사용자의 접근 시 적절한 로그인 페이지로 리다이렉트하거나 JSON 에러 응답을 반환합니다.
 *
 * 주요 기능:
 * 1. HTML 요청 → DSL 설정된 loginPage로 리다이렉트
 * 2. API/AJAX 요청 → JSON 형식 에러 응답 반환
 * 3. DSL 설정(AuthenticationFlowConfig)에서 자동 생성됨
 *
 * 사용 예시:
 * <pre>
 * // MfaDslConfigurerImpl에서 자동 생성
 * String loginPageUrl = primaryAuth.getLoginPage();  // "/loginForm" 또는 커스텀 페이지
 * MfaAuthenticationEntryPoint entryPoint = new MfaAuthenticationEntryPoint(objectMapper, loginPageUrl);
 *
 * // HttpSecurity에 기본 EntryPoint로 등록
 * exceptionHandling.defaultAuthenticationEntryPointFor(entryPoint, matcher);
 * </pre>
 *
 * @see org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
 * @see io.contexa.contexaidentity.security.core.dsl.configurer.impl.MfaDslConfigurerImpl
 */
public class MfaAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;
    private final String loginPageUrl;  // ⭐ DSL 설정에서 가져온 로그인 페이지 URL

    /**
     * Constructor
     *
     * @param objectMapper JSON 직렬화를 위한 ObjectMapper
     * @param loginPageUrl 로그인 페이지 URL (DSL 설정값 또는 기본값)
     * @throws IllegalArgumentException loginPageUrl이 null이거나 빈 문자열인 경우
     */
    public MfaAuthenticationEntryPoint(ObjectMapper objectMapper, String loginPageUrl) {
        Assert.notNull(objectMapper, "ObjectMapper cannot be null");
        Assert.hasText(loginPageUrl, "loginPageUrl cannot be null or empty");

        this.objectMapper = objectMapper;
        this.loginPageUrl = loginPageUrl;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException {

        if (WebUtil.isApiOrAjaxRequest(request)) {
            // API/AJAX 요청 → JSON 에러 응답
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

        } else {
            // HTML 요청 → DSL 설정된 로그인 페이지로 리다이렉트
            response.sendRedirect(this.loginPageUrl);  // ⭐ DSL 설정 사용
        }
    }

    /**
     * 설정된 로그인 페이지 URL 반환
     *
     * @return 로그인 페이지 URL
     */
    public String getLoginPageUrl() {
        return this.loginPageUrl;
    }
}
