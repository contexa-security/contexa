package io.contexa.contexaidentity.security.exceptionhandling;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaidentity.domain.ErrorResponse;
import io.contexa.contexacommon.enums.ErrorCode;
import io.contexa.contexacommon.properties.MfaPageConfig;
import io.contexa.contexaidentity.security.utils.WebUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
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
 * 3. 모든 MFA 페이지 종류 지원 (Spring Security 7.0 패턴)
 *    - Primary Auth: FormLogin/RestLogin/OTT/Passkey
 *    - MFA Challenge: Select Factor, OTT Verify, Passkey Challenge
 *    - Utility: Configure, Failure
 * 4. DSL 설정(AuthenticationFlowConfig)에서 자동 생성됨
 * 5. HTTPS 강제 전환 지원 (forceHttps - 부모 클래스 기능)
 * 6. Forward/Redirect 선택 가능 (useForward - 부모 클래스 기능)
 * 7. PortMapper 지원 (부모 클래스 기능)
 *
 * 로그인 페이지 결정 로직 (factor.type 파라미터 또는 URI 패턴 기반):
 * - factor.type=ott → OTT Request 페이지
 * - factor.type=passkey 또는 webauthn → Passkey Challenge 페이지
 * - factor.type=select → Select Factor 페이지
 * - factor.type=configure → Configure 페이지
 * - 기본 → Primary Auth 페이지 (FormLogin/RestLogin)
 *
 * 상속 구조:
 * - LoginUrlAuthenticationEntryPoint (부모)
 *   - forceHttps, useForward, PortMapper, buildRedirectUrlToLoginPage() 등 제공
 * - MfaAuthenticationEntryPoint (자식)
 *   - API/AJAX 요청 시 JSON 에러 응답 추가
 *   - 모든 MFA 페이지 종류별 라우팅 지원
 *
 * 사용 예시:
 * <pre>
 * // MfaDslConfigurerImpl에서 자동 생성
 * MfaAuthenticationEntryPoint entryPoint = new MfaAuthenticationEntryPoint(
 *     objectMapper,
 *     loginPageUrl,
 *     mfaPageConfig  // DSL 설정된 커스텀 페이지 URL
 * );
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
 * @see org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter (Spring Security 7.0 참고)
 */
@Slf4j
public class MfaAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint {

    private final ObjectMapper objectMapper;
    private final MfaPageConfig mfaPageConfig;

    /**
     * Constructor
     *
     * @param objectMapper JSON 직렬화를 위한 ObjectMapper
     * @param loginPageUrl 로그인 페이지 URL (DSL 설정값 또는 기본값)
     * @param mfaPageConfig MFA 커스텀 페이지 설정 (DSL .mfaPage()로 설정, null 허용)
     * @throws IllegalArgumentException objectMapper가 null이거나 loginPageUrl이 유효하지 않은 경우
     */
    public MfaAuthenticationEntryPoint(ObjectMapper objectMapper, String loginPageUrl, MfaPageConfig mfaPageConfig) {
        super(loginPageUrl);  // ⭐ 부모 클래스 생성자 호출
        Assert.notNull(objectMapper, "ObjectMapper cannot be null");
        this.objectMapper = objectMapper;
        this.mfaPageConfig = mfaPageConfig;  // ⭐ MfaPageConfig 저장 (null 허용)
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

    /**
     * 요청에 적합한 로그인 페이지 URL 결정
     *
     * <p>
     * Spring Security 7.0의 LoginUrlAuthenticationEntryPoint 패턴을 참고하여
     * factor.type 파라미터 또는 Request URI 분석을 통해 적절한 인증 페이지로 리다이렉트합니다.
     * </p>
     *
     * <p>
     * 우선순위:
     * 1. factor.type 파라미터 (명시적 요청) - Spring Security 7.0 패턴
     * 2. Request URI 패턴 분석 (암시적 요청) - 우리 플랫폼 확장
     * 3. Primary Auth 페이지 (기본값) - 부모 클래스
     * </p>
     *
     * <p>
     * 지원하는 MFA 페이지 종류:
     * - factor.type=select → Select Factor 페이지
     * - factor.type=ott → OTT Request 페이지
     * - factor.type=ott-verify → OTT Verify 페이지
     * - factor.type=passkey 또는 webauthn → Passkey Challenge 페이지
     * - factor.type=configure → Configure 페이지
     * - factor.type=failure → Failure 페이지
     * - 기본 → Primary Auth 페이지 (FormLogin/RestLogin)
     * </p>
     *
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @param exception 인증 예외
     * @return 리다이렉트할 로그인 페이지 URL
     * @see org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint#determineUrlToUseForThisRequest
     */
    @Override
    protected String determineUrlToUseForThisRequest(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception) {

        // Step 1: factor.type 파라미터 확인 (Spring Security 7.0 패턴)
        String factorType = request.getParameter("factor.type");

        // Step 2: Select Factor 페이지 (MFA Factor 선택)
        if ("select".equalsIgnoreCase(factorType) || isSelectFactorRequest(request)) {
            String selectFactorUrl = getSelectFactorPageUrl();
            log.debug("Redirecting to Select Factor page: {}", selectFactorUrl);
            return selectFactorUrl;
        }

        // Step 3: OTT Request 페이지 (OTT 코드 요청)
        if ("ott".equalsIgnoreCase(factorType) || isOttRequestPageRequest(request)) {
            String ottRequestUrl = getOttRequestPageUrl();
            log.debug("Redirecting to OTT Request page: {}", ottRequestUrl);
            return ottRequestUrl;
        }

        // Step 4: OTT Verify 페이지 (OTT 코드 검증)
        if ("ott-verify".equalsIgnoreCase(factorType) || isOttVerifyPageRequest(request)) {
            String ottVerifyUrl = getOttVerifyPageUrl();
            log.debug("Redirecting to OTT Verify page: {}", ottVerifyUrl);
            return ottVerifyUrl;
        }

        // Step 5: Passkey Challenge 페이지 (Passkey/WebAuthn 인증)
        if ("passkey".equalsIgnoreCase(factorType) ||
                "webauthn".equalsIgnoreCase(factorType) ||
                isPasskeyChallengeRequest(request)) {
            String passkeyUrl = getPasskeyChallengePageUrl();
            log.debug("Redirecting to Passkey Challenge page: {}", passkeyUrl);
            return passkeyUrl;
        }

        // Step 6: Configure 페이지 (MFA 초기 설정)
        if ("configure".equalsIgnoreCase(factorType) || isConfigurePageRequest(request)) {
            String configureUrl = getConfigurePageUrl();
            log.debug("Redirecting to MFA Configure page: {}", configureUrl);
            return configureUrl;
        }

        // Step 7: Failure 페이지 (MFA 인증 실패)
        if ("failure".equalsIgnoreCase(factorType) || isFailurePageRequest(request)) {
            String failureUrl = getFailurePageUrl();
            log.debug("Redirecting to MFA Failure page: {}", failureUrl);
            return failureUrl;
        }

        // Step 8: 기본 Primary Auth 페이지 (부모 클래스)
        return getLoginFormUrl();  // "/loginForm" 또는 DSL 설정값
    }

    // ========== MFA 페이지 URL 반환 헬퍼 메서드 ==========

    /**
     * Select Factor 페이지 URL 반환
     *
     * <p>
     * 우선순위:
     * 1. MfaPageConfig.selectFactorPageUrl (DSL 커스텀 설정)
     * 2. DefaultMfaPageGeneratingFilter 기본값 (/mfa/select-factor)
     * </p>
     *
     * @return Select Factor 페이지 URL
     */
    private String getSelectFactorPageUrl() {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomSelectFactorPage()) {
            return mfaPageConfig.getSelectFactorPageUrl();
        }
        return "/mfa/select-factor";  // DefaultMfaPageGeneratingFilter 기본값
    }

    /**
     * OTT Request 페이지 URL 반환
     *
     * <p>
     * 우선순위:
     * 1. MfaPageConfig.ottRequestPageUrl (DSL 커스텀 설정)
     * 2. DefaultMfaPageGeneratingFilter 기본값 (/mfa/ott/request-code-ui)
     * </p>
     *
     * @return OTT Request 페이지 URL
     */
    private String getOttRequestPageUrl() {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomOttRequestPage()) {
            return mfaPageConfig.getOttRequestPageUrl();
        }
        return "/mfa/ott/request-code-ui";  // DefaultMfaPageGeneratingFilter 기본값
    }

    /**
     * OTT Verify 페이지 URL 반환
     *
     * <p>
     * 우선순위:
     * 1. MfaPageConfig.ottVerifyPageUrl (DSL 커스텀 설정)
     * 2. DefaultMfaPageGeneratingFilter 기본값 (/mfa/challenge/ott)
     * </p>
     *
     * @return OTT Verify 페이지 URL
     */
    private String getOttVerifyPageUrl() {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomOttVerifyPage()) {
            return mfaPageConfig.getOttVerifyPageUrl();
        }
        return "/mfa/challenge/ott";  // DefaultMfaPageGeneratingFilter 기본값
    }

    /**
     * Passkey Challenge 페이지 URL 반환
     *
     * <p>
     * 우선순위:
     * 1. MfaPageConfig.passkeyChallengePageUrl (DSL 커스텀 설정)
     * 2. DefaultMfaPageGeneratingFilter 기본값 (/mfa/challenge/passkey)
     * </p>
     *
     * @return Passkey Challenge 페이지 URL
     */
    private String getPasskeyChallengePageUrl() {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomPasskeyPage()) {
            return mfaPageConfig.getPasskeyChallengePageUrl();
        }
        return "/mfa/challenge/passkey";  // DefaultMfaPageGeneratingFilter 기본값
    }

    /**
     * Configure 페이지 URL 반환
     *
     * <p>
     * 우선순위:
     * 1. MfaPageConfig.configurePageUrl (DSL 커스텀 설정)
     * 2. DefaultMfaPageGeneratingFilter 기본값 (/mfa/configure)
     * </p>
     *
     * @return Configure 페이지 URL
     */
    private String getConfigurePageUrl() {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomConfigurePage()) {
            return mfaPageConfig.getConfigurePageUrl();
        }
        return "/mfa/configure";  // DefaultMfaPageGeneratingFilter 기본값
    }

    /**
     * Failure 페이지 URL 반환
     *
     * <p>
     * 우선순위:
     * 1. MfaPageConfig.failurePageUrl (DSL 커스텀 설정)
     * 2. DefaultMfaPageGeneratingFilter 기본값 (/mfa/failure)
     * </p>
     *
     * @return Failure 페이지 URL
     */
    private String getFailurePageUrl() {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomFailurePage()) {
            return mfaPageConfig.getFailurePageUrl();
        }
        return "/mfa/failure";  // DefaultMfaPageGeneratingFilter 기본값
    }

    // ========== 요청 타입 판별 헬퍼 메서드 ==========

    /**
     * Select Factor 페이지 요청 여부 판별
     *
     * <p>
     * 판별 기준:
     * - URI에 "/mfa/select-factor" 포함
     * - URI에 "/select-factor" 포함
     * </p>
     *
     * @param request HTTP 요청
     * @return Select Factor 페이지 요청이면 true
     */
    private boolean isSelectFactorRequest(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri.contains("/mfa/select-factor") ||
                uri.contains("/select-factor");
    }

    /**
     * OTT Request 페이지 요청 여부 판별
     *
     * <p>
     * 판별 기준:
     * - URI에 "/loginOtt" 포함
     * - URI에 "/ott/request" 포함
     * - URI에 "/mfa/ott/request" 포함
     * </p>
     *
     * @param request HTTP 요청
     * @return OTT Request 페이지 요청이면 true
     */
    private boolean isOttRequestPageRequest(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri.contains("/loginOtt") ||
                uri.contains("/ott/request") ||
                uri.contains("/mfa/ott/request");
    }

    /**
     * OTT Verify 페이지 요청 여부 판별
     *
     * <p>
     * 판별 기준:
     * - URI에 "/ott/verify" 포함
     * - URI에 "/challenge/ott" 포함
     * - URI에 "/mfa/challenge/ott" 포함
     * </p>
     *
     * @param request HTTP 요청
     * @return OTT Verify 페이지 요청이면 true
     */
    private boolean isOttVerifyPageRequest(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri.contains("/ott/verify") ||
                uri.contains("/challenge/ott") ||
                uri.contains("/mfa/challenge/ott");
    }

    /**
     * Passkey Challenge 페이지 요청 여부 판별
     *
     * <p>
     * 판별 기준:
     * - URI에 "/loginPasskey" 포함
     * - URI에 "/webauthn/" 포함
     * - URI에 "/passkey" 포함
     * - URI에 "/challenge/passkey" 포함
     * </p>
     *
     * @param request HTTP 요청
     * @return Passkey Challenge 페이지 요청이면 true
     */
    private boolean isPasskeyChallengeRequest(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri.contains("/loginPasskey") ||
                uri.contains("/webauthn/") ||
                uri.contains("/passkey") ||
                uri.contains("/challenge/passkey");
    }

    /**
     * Configure 페이지 요청 여부 판별
     *
     * <p>
     * 판별 기준:
     * - URI에 "/mfa/configure" 포함
     * - URI에 "/configure" 포함
     * </p>
     *
     * @param request HTTP 요청
     * @return Configure 페이지 요청이면 true
     */
    private boolean isConfigurePageRequest(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri.contains("/mfa/configure") ||
                uri.contains("/configure");
    }

    /**
     * Failure 페이지 요청 여부 판별
     *
     * <p>
     * 판별 기준:
     * - URI에 "/mfa/failure" 포함
     * - URI에 "/failure" 포함
     * </p>
     *
     * @param request HTTP 요청
     * @return Failure 페이지 요청이면 true
     */
    private boolean isFailurePageRequest(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri.contains("/mfa/failure") ||
                uri.contains("/failure");
    }
}
