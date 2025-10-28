package io.contexa.contexaidentity.security.filter;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexaidentity.security.core.dsl.option.RestOptions;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.properties.MfaPageConfig;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Default MFA Page Generating Filter
 *
 * Spring Security 7.0의 DefaultLoginPageGeneratingFilter 패턴을 적용한 MFA 페이지 생성 필터.
 * DSL 설정(AuthenticationFlowConfig)을 기반으로 MFA 플로우의 모든 페이지를 생성합니다.
 *
 * 주요 기능:
 * 1. Primary Authentication (1차 인증) 페이지 생성 - Form Login 또는 REST
 * 2. MFA Select Factor (2차 인증 선택) 페이지 생성
 * 3. Factor Challenge (개별 Factor 챌린지) 페이지 생성 - OTT, Passkey 등
 * 4. 커스텀 페이지가 설정된 경우 해당 URL로 forward
 * 5. FactorContext를 request attribute로 자동 주입
 * 6. contexa-mfa-sdk.js 스크립트 자동 주입
 *
 * 페이지 표시 순서:
 * 1. Primary Auth Page (loginPage) - 사용자 ID/PW 입력
 * 2. Select Factor Page - 등록된 2차 인증 방법 선택
 * 3. Factor Challenge Page - 선택된 Factor의 챌린지 페이지
 *
 * 사용 예시:
 * <pre>
 * .mfa(mfa -> mfa
 *     .primaryAuthentication(primary -> primary
 *         .formLogin(form -> form.loginPage("/custom/login"))  // 커스텀 1차 인증 페이지
 *     )
 *     .mfaPage(page -> page
 *         .selectFactorPage("/custom/mfa/select")  // 커스텀 2차 인증 선택 페이지
 *         .ottPages("/custom/mfa/ott-request", "/custom/mfa/ott-verify")
 *     )
 * )
 * </pre>
 *
 * @see org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter
 */
@Slf4j
public class DefaultMfaPageGeneratingFilter extends OncePerRequestFilter {

    private final AuthenticationFlowConfig mfaFlowConfig;
    private final MfaStateMachineIntegrator stateMachineIntegrator;

    /**
     * Constructor
     *
     * @param mfaFlowConfig DSL로 구성된 MFA 플로우 설정 (AuthenticationFlowConfig)
     * @param stateMachineIntegrator MFA State Machine 통합 객체
     * @throws IllegalArgumentException MFA 플로우가 아닌 경우
     */
    public DefaultMfaPageGeneratingFilter(
            AuthenticationFlowConfig mfaFlowConfig,
            MfaStateMachineIntegrator stateMachineIntegrator) {
        Assert.notNull(mfaFlowConfig, "AuthenticationFlowConfig cannot be null");
        Assert.isTrue(AuthType.MFA.name().equalsIgnoreCase(mfaFlowConfig.getTypeName()),
                "This filter only works with MFA flow config. Provided flow type: " + mfaFlowConfig.getTypeName());
        Assert.notNull(stateMachineIntegrator, "MfaStateMachineIntegrator cannot be null");

        this.mfaFlowConfig = mfaFlowConfig;
        this.stateMachineIntegrator = stateMachineIntegrator;

        log.info("✅ DefaultMfaPageGeneratingFilter initialized for MFA flow. Primary auth page: {}, Select factor page: {}",
                extractPrimaryLoginPage(),
                extractSelectFactorUrl());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain chain) throws ServletException, IOException {

        String requestUri = normalizeUri(request);

        // Step 1: Primary Authentication Page (1차 인증) - 최우선 처리
        if (isPrimaryAuthPage(requestUri)) {
            handlePrimaryAuthPage(request, response);
            return;
        }

        // Step 2: MFA Select Factor Page (2차 인증 선택)
        if (isSelectFactorPage(requestUri)) {
            handleSelectFactorPage(request, response);
            return;
        }

        // Step 3: Factor Challenge Pages (개별 Factor 챌린지)

        // OTT Request Code Page
        if (isOttRequestPage(requestUri)) {
            handleOttRequestPage(request, response);
            return;
        }

        // OTT Verify Page
        if (isOttChallengePage(requestUri)) {
            handleOttChallengePage(request, response);
            return;
        }

        // Passkey Challenge Page
        if (isPasskeyChallengePage(requestUri)) {
            handlePasskeyChallengePage(request, response);
            return;
        }

        // Step 4: MFA Utility Pages

        // MFA Configure Page
        if (isConfigurePage(requestUri)) {
            handleConfigurePage(request, response);
            return;
        }

        // MFA Failure Page
        if (isFailurePage(requestUri)) {
            handleFailurePage(request, response);
            return;
        }

        chain.doFilter(request, response);
    }

    // ===== Primary Authentication (1차 인증) =====

    /**
     * Primary Authentication 페이지 요청 여부 확인
     */
    private boolean isPrimaryAuthPage(String requestUri) {
        String primaryLoginPage = extractPrimaryLoginPage();
        return requestUri.equals(primaryLoginPage);
    }

    /**
     * Primary Authentication 페이지 처리
     */
    private void handlePrimaryAuthPage(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        PrimaryAuthenticationOptions primaryOpts = mfaFlowConfig.getPrimaryAuthenticationOptions();
        if (primaryOpts == null) {
            log.warn("⚠️ Primary authentication options not configured for MFA flow. Skipping primary auth page generation.");
            return;
        }

        if (primaryOpts.isFormLogin()) {
            FormOptions formOpts = primaryOpts.getFormOptions();

            // 커스텀 로그인 페이지가 명시적으로 설정된 경우
            if (isCustomLoginPage(formOpts)) {
                log.debug("Forwarding to custom primary login page: {}", formOpts.getLoginPage());
                forwardToCustomPage(request, response, formOpts.getLoginPage());
            } else {
                // 기본 로그인 페이지 생성
                log.debug("Generating default primary form login page");
                generatePrimaryFormLoginPage(request, response, formOpts);
            }
        } else if (primaryOpts.isRestLogin()) {
            // ⭐ REST 인증도 HTML 페이지 필요 (JavaScript가 비동기 인증 처리)
            RestOptions restOpts = primaryOpts.getRestOptions();
            String loginPage = primaryOpts.getLoginPage(); // PrimaryAuthenticationOptions에서 가져옴

            // 커스텀 로그인 페이지가 명시적으로 설정된 경우
            if (StringUtils.hasText(loginPage) && !"/loginForm".equals(loginPage)) {
                log.debug("Forwarding to custom primary REST login page: {}", loginPage);
                forwardToCustomPage(request, response, loginPage);
            } else {
                // 기본 REST 로그인 페이지 생성 (JavaScript 기반)
                log.debug("Generating default primary REST login page");
                generatePrimaryRestLoginPage(request, response, restOpts);
            }
        }
    }

    /**
     * Primary Login Page URL 추출 (DSL 설정 기반)
     */
    private String extractPrimaryLoginPage() {
        PrimaryAuthenticationOptions primaryOpts = mfaFlowConfig.getPrimaryAuthenticationOptions();
        if (primaryOpts != null && primaryOpts.isFormLogin()) {
            FormOptions formOpts = primaryOpts.getFormOptions();
            return StringUtils.hasText(formOpts.getLoginPage()) ?
                    formOpts.getLoginPage() : "/loginForm"; // 기본값
        }
        return "/loginForm"; // 폴백 기본값
    }

    /**
     * 커스텀 로그인 페이지 여부 확인
     *
     * Spring Security 패턴: 기본값과 다른 값이 설정되었는지 확인
     */
    private boolean isCustomLoginPage(FormOptions formOpts) {
        String loginPage = formOpts.getLoginPage();
        // loginPage가 명시적으로 설정되고 기본값("/loginForm")과 다른 경우 커스텀으로 판단
        return StringUtils.hasText(loginPage) && !"/loginForm".equals(loginPage);
    }

    // ===== MFA Select Factor Page (2차 인증 선택) =====

    /**
     * Select Factor 페이지 요청 여부 확인
     */
    private boolean isSelectFactorPage(String requestUri) {
        String selectFactorUrl = extractSelectFactorUrl();
        return requestUri.equals(selectFactorUrl);
    }

    /**
     * Select Factor 페이지 처리
     */
    private void handleSelectFactorPage(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();

        if (pageConfig != null && pageConfig.hasCustomSelectFactorPage()) {
            log.debug("Forwarding to custom select factor page: {}", pageConfig.getSelectFactorPageUrl());
            forwardToCustomPage(request, response, pageConfig.getSelectFactorPageUrl());
        } else {
            log.debug("Generating default select factor page");
            generateSelectFactorPage(request, response);
        }
    }

    /**
     * Select Factor URL 추출 (DSL 설정 + 기본값 폴백)
     */
    private String extractSelectFactorUrl() {
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        if (pageConfig != null && StringUtils.hasText(pageConfig.getSelectFactorPageUrl())) {
            return pageConfig.getSelectFactorPageUrl();
        }
        return "/mfa/select-factor"; // 기본값
    }

    // ===== OTT Challenge Pages =====

    /**
     * OTT Request 페이지 요청 여부 확인
     */
    private boolean isOttRequestPage(String requestUri) {
        String ottRequestUrl = extractOttRequestUrl();
        return requestUri.equals(ottRequestUrl);
    }

    /**
     * OTT Request 페이지 처리
     */
    private void handleOttRequestPage(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();

        if (pageConfig != null && pageConfig.hasCustomOttRequestPage()) {
            log.debug("Forwarding to custom OTT request page: {}", pageConfig.getOttRequestPageUrl());
            forwardToCustomPage(request, response, pageConfig.getOttRequestPageUrl());
        } else {
            log.debug("Generating default OTT request page");
            generateOttRequestCodePage(request, response);
        }
    }

    /**
     * OTT Challenge 페이지 요청 여부 확인
     */
    private boolean isOttChallengePage(String requestUri) {
        String ottChallengeUrl = extractOttChallengeUrl();
        return requestUri.equals(ottChallengeUrl);
    }

    /**
     * OTT Challenge 페이지 처리
     */
    private void handleOttChallengePage(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();

        if (pageConfig != null && pageConfig.hasCustomOttVerifyPage()) {
            log.debug("Forwarding to custom OTT verify page: {}", pageConfig.getOttVerifyPageUrl());
            forwardToCustomPage(request, response, pageConfig.getOttVerifyPageUrl());
        } else {
            log.debug("Generating default OTT verify page");
            generateOttVerifyPage(request, response);
        }
    }

    /**
     * OTT Request URL 추출 (DSL 설정 + 기본값 폴백)
     */
    private String extractOttRequestUrl() {
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        if (pageConfig != null && StringUtils.hasText(pageConfig.getOttRequestPageUrl())) {
            return pageConfig.getOttRequestPageUrl();
        }
        return "/mfa/ott/request-code-ui"; // 기본값
    }

    /**
     * OTT Challenge URL 추출 (DSL 설정 + 기본값 폴백)
     */
    private String extractOttChallengeUrl() {
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        if (pageConfig != null && StringUtils.hasText(pageConfig.getOttVerifyPageUrl())) {
            return pageConfig.getOttVerifyPageUrl();
        }
        return "/mfa/challenge/ott"; // 기본값
    }

    // ===== Passkey Challenge Page =====

    /**
     * Passkey Challenge 페이지 요청 여부 확인
     */
    private boolean isPasskeyChallengePage(String requestUri) {
        String passkeyUrl = extractPasskeyChallengeUrl();
        return requestUri.equals(passkeyUrl);
    }

    /**
     * Passkey Challenge 페이지 처리
     */
    private void handlePasskeyChallengePage(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();

        if (pageConfig != null && pageConfig.hasCustomPasskeyPage()) {
            log.debug("Forwarding to custom Passkey challenge page: {}", pageConfig.getPasskeyChallengePageUrl());
            forwardToCustomPage(request, response, pageConfig.getPasskeyChallengePageUrl());
        } else {
            log.debug("Generating default Passkey challenge page");
            generatePasskeyChallengePage(request, response);
        }
    }

    /**
     * Passkey Challenge URL 추출 (DSL 설정 + 기본값 폴백)
     */
    private String extractPasskeyChallengeUrl() {
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        if (pageConfig != null && StringUtils.hasText(pageConfig.getPasskeyChallengePageUrl())) {
            return pageConfig.getPasskeyChallengePageUrl();
        }
        return "/mfa/challenge/passkey"; // 기본값
    }

    // ===== Utility Pages =====

    /**
     * Configure 페이지 요청 여부 확인
     */
    private boolean isConfigurePage(String requestUri) {
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        if (pageConfig != null && StringUtils.hasText(pageConfig.getConfigurePageUrl())) {
            return requestUri.equals(pageConfig.getConfigurePageUrl());
        }
        return requestUri.equals("/mfa/configure"); // 기본값
    }

    /**
     * Configure 페이지 처리
     */
    private void handleConfigurePage(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();

        if (pageConfig != null && pageConfig.hasCustomConfigurePage()) {
            log.debug("Forwarding to custom configure page: {}", pageConfig.getConfigurePageUrl());
            forwardToCustomPage(request, response, pageConfig.getConfigurePageUrl());
        } else {
            log.debug("Generating default configure page");
            generateConfigurePage(request, response);
        }
    }

    /**
     * Failure 페이지 요청 여부 확인
     */
    private boolean isFailurePage(String requestUri) {
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        if (pageConfig != null && StringUtils.hasText(pageConfig.getFailurePageUrl())) {
            return requestUri.equals(pageConfig.getFailurePageUrl());
        }
        return requestUri.equals("/mfa/failure"); // 기본값
    }

    /**
     * Failure 페이지 처리
     */
    private void handleFailurePage(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();

        if (pageConfig != null && pageConfig.hasCustomFailurePage()) {
            log.debug("Forwarding to custom failure page: {}", pageConfig.getFailurePageUrl());
            forwardToCustomPage(request, response, pageConfig.getFailurePageUrl());
        } else {
            log.debug("Generating default failure page");
            generateFailurePage(request, response);
        }
    }

    // ===== Utility Methods =====

    /**
     * Request URI 정규화 (Context Path 제거)
     */
    private String normalizeUri(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        String contextPath = request.getContextPath();

        if (StringUtils.hasText(contextPath)) {
            requestUri = requestUri.substring(contextPath.length());
        }

        return requestUri;
    }

    /**
     * 커스텀 페이지로 forward
     */
    private void forwardToCustomPage(HttpServletRequest request,
                                     HttpServletResponse response,
                                     String customPageUrl) throws ServletException, IOException {
        // FactorContext를 request attribute로 주입
        injectFactorContextAsAttributes(request);

        log.debug("Forwarding to custom MFA page: {}", customPageUrl);
        request.getRequestDispatcher(customPageUrl).forward(request, response);
    }

    /**
     * FactorContext를 request attributes로 주입
     */
    private void injectFactorContextAsAttributes(HttpServletRequest request) {
        try {
            FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);
            if (ctx != null) {
                request.setAttribute("mfaSessionId", ctx.getMfaSessionId());
                request.setAttribute("username", ctx.getUsername());
                request.setAttribute("currentState", ctx.getCurrentState() != null ? ctx.getCurrentState().name() : null);
                request.setAttribute("flowType", ctx.getFlowTypeName());
                request.setAttribute("registeredFactors", ctx.getRegisteredMfaFactors());
                request.setAttribute("completedFactors", ctx.getCompletedFactors());
                request.setAttribute("currentProcessingFactor", ctx.getCurrentProcessingFactor());
                request.setAttribute("currentStepId", ctx.getCurrentStepId());
            }
        } catch (Exception e) {
            log.error("Failed to inject FactorContext as attributes", e);
        }
    }

    /**
     * Select Factor Page 생성
     */
    private void generateSelectFactorPage(HttpServletRequest request, HttpServletResponse response) throws IOException {
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);

        response.setContentType("text/html;charset=UTF-8");
        PrintWriter writer = response.getWriter();

        List<String> factorNames = ctx != null && ctx.getRegisteredMfaFactors() != null ?
                ctx.getRegisteredMfaFactors().stream().map(AuthType::name).collect(Collectors.toList()) :
                List.of();

        String html = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MFA - 인증 방법 선택</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 480px; margin: 50px auto; background: white; padding: 32px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        h1 { margin: 0 0 24px; font-size: 24px; color: #333; }
        .factor-list { list-style: none; padding: 0; margin: 0; }
        .factor-item { margin-bottom: 12px; }
        .factor-button { width: 100%; padding: 16px; border: 1px solid #ddd; background: white; border-radius: 6px; font-size: 16px; cursor: pointer; transition: all 0.2s; }
        .factor-button:hover { border-color: #007bff; background: #f8f9fa; }
        .message { padding: 12px; margin-bottom: 16px; border-radius: 6px; }
        .message.info { background: #d1ecf1; color: #0c5460; }
        .message.error { background: #f8d7da; color: #721c24; }
    </style>
    <script src="/js/contexa-mfa-sdk.js"></script>
</head>
<body>
    <div class="container">
        <h1>인증 방법을 선택하세요</h1>
        <div id="message-container"></div>
        <ul class="factor-list" id="factor-list">
            <!-- SDK가 동적으로 생성 -->
        </ul>
    </div>

    <script>
        (async function() {
            try {
                const mfa = new ContexaMFA.Client({ autoRedirect: true });
                const context = await mfa.init();

                const factorList = document.getElementById('factor-list');
                const messageContainer = document.getElementById('message-container');

                if (!context.registeredFactors || context.registeredFactors.length === 0) {
                    messageContainer.innerHTML = '<div class="message error">등록된 인증 방법이 없습니다.</div>';
                    return;
                }

                context.registeredFactors.forEach(factor => {
                    const li = document.createElement('li');
                    li.className = 'factor-item';

                    const button = document.createElement('button');
                    button.className = 'factor-button';
                    button.textContent = getFactorDisplayName(factor);
                    button.onclick = async () => {
                        button.disabled = true;
                        button.textContent = '처리 중...';

                        try {
                            await mfa.selectFactor(factor);
                        } catch (error) {
                            messageContainer.innerHTML = `<div class="message error">${error.message}</div>`;
                            button.disabled = false;
                            button.textContent = getFactorDisplayName(factor);
                        }
                    };

                    li.appendChild(button);
                    factorList.appendChild(li);
                });
            } catch (error) {
                console.error('Failed to initialize MFA', error);
                document.getElementById('message-container').innerHTML =
                    `<div class="message error">MFA 초기화 실패: ${error.message}</div>`;
            }
        })();

        function getFactorDisplayName(factor) {
            const names = {
                'OTT': '이메일 인증 코드 (OTT)',
                'PASSKEY': 'Passkey 생체 인증',
                'TOTP': '인증 앱 (TOTP)',
                'SMS': 'SMS 인증'
            };
            return names[factor] || factor;
        }
    </script>
</body>
</html>
                """;

        writer.write(html);
        writer.flush();

        log.debug("Generated default select factor page for session: {}",
                ctx != null ? ctx.getMfaSessionId() : "unknown");
    }

    /**
     * Primary Form Login Page 생성 (기본 1차 인증 페이지)
     */
    private void generatePrimaryFormLoginPage(HttpServletRequest request, HttpServletResponse response, FormOptions formOpts)
            throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter writer = response.getWriter();

        String loginProcessingUrl = formOpts.getLoginProcessingUrl();
        String usernameParam = formOpts.getUsernameParameter();
        String passwordParam = formOpts.getPasswordParameter();

        String errorMessage = request.getParameter("error");
        String logoutMessage = request.getParameter("logout");

        String html = String.format("""
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>로그인 - MFA 인증</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 32px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        h1 { margin: 0 0 24px; font-size: 24px; color: #333; text-align: center; }
        .message { padding: 12px; margin-bottom: 16px; border-radius: 6px; }
        .message.error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .message.success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        input { width: 100%%; padding: 12px; margin-bottom: 16px; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; font-size: 14px; }
        input:focus { outline: none; border-color: #007bff; }
        button { width: 100%%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }
        button:hover { background: #0056b3; }
        button:disabled { background: #6c757d; cursor: not-allowed; }
        .form-footer { margin-top: 16px; text-align: center; font-size: 14px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 로그인</h1>
        %s
        %s
        <form method="post" action="%s">
            <input type="text" name="%s" placeholder="사용자명 또는 이메일" required autofocus>
            <input type="password" name="%s" placeholder="비밀번호" required>
            <button type="submit">로그인</button>
        </form>
        <div class="form-footer">
            로그인 후 다단계 인증(MFA)이 진행됩니다.
        </div>
    </div>
</body>
</html>
                """,
                errorMessage != null ? "<div class=\"message error\">⚠️ 로그인 실패: 사용자명 또는 비밀번호를 확인하세요.</div>" : "",
                logoutMessage != null ? "<div class=\"message success\">✅ 로그아웃되었습니다.</div>" : "",
                loginProcessingUrl,
                usernameParam,
                passwordParam
        );

        writer.write(html);
        writer.flush();

        log.debug("Generated default primary form login page for MFA flow. Processing URL: {}", loginProcessingUrl);
    }

    /**
     * Primary REST Login Page 생성
     *
     * REST 인증용 HTML 페이지를 생성합니다.
     * JavaScript를 사용하여 비동기로 인증 요청을 처리합니다.
     *
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @param restOpts REST 인증 옵션
     * @throws IOException 페이지 생성 실패 시
     */
    private void generatePrimaryRestLoginPage(HttpServletRequest request, HttpServletResponse response, RestOptions restOpts)
            throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter writer = response.getWriter();

        String loginProcessingUrl = restOpts.getLoginProcessingUrl();
        String usernameParam = restOpts.getUsernameParameter();
        String passwordParam = restOpts.getPasswordParameter();

        String errorMessage = request.getParameter("error");
        String logoutMessage = request.getParameter("logout");

        String html = String.format("""
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>로그인 - MFA 인증 (REST)</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 32px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        h1 { margin: 0 0 24px; font-size: 24px; color: #333; text-align: center; }
        .message { padding: 12px; margin-bottom: 16px; border-radius: 6px; }
        .message.error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .message.success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .message.info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
        input { width: 100%%; padding: 12px; margin-bottom: 16px; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; font-size: 14px; }
        input:focus { outline: none; border-color: #007bff; }
        button { width: 100%%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }
        button:hover { background: #0056b3; }
        button:disabled { background: #6c757d; cursor: not-allowed; }
        .form-footer { margin-top: 16px; text-align: center; font-size: 14px; color: #666; }
        .spinner { display: none; text-align: center; margin-top: 8px; }
        .spinner.active { display: block; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 로그인 (REST API)</h1>
        <div id="message-area">
            %s
            %s
        </div>
        <form id="loginForm">
            <input type="text" id="username" name="%s" placeholder="사용자명 또는 이메일" required autofocus>
            <input type="password" id="password" name="%s" placeholder="비밀번호" required>
            <button type="submit" id="loginButton">로그인</button>
            <div class="spinner" id="spinner">⏳ 인증 중...</div>
        </form>
        <div class="form-footer">
            로그인 후 다단계 인증(MFA)이 진행됩니다.
        </div>
    </div>

    <script>
        const form = document.getElementById('loginForm');
        const messageArea = document.getElementById('message-area');
        const loginButton = document.getElementById('loginButton');
        const spinner = document.getElementById('spinner');

        form.addEventListener('submit', async (e) => {
            e.preventDefault();

            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            // UI 상태 변경
            loginButton.disabled = true;
            spinner.classList.add('active');
            messageArea.innerHTML = '';

            try {
                const response = await fetch('%s', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        %s: username,
                        %s: password
                    })
                });

                const data = await response.json();

                if (response.ok) {
                    // 성공 - MFA Select Factor 페이지로 리다이렉트
                    messageArea.innerHTML = '<div class="message success">✅ 로그인 성공! 다단계 인증을 진행합니다...</div>';
                    setTimeout(() => {
                        window.location.href = data.redirectUrl || '/mfa/select-factor';
                    }, 1000);
                } else {
                    // 실패
                    messageArea.innerHTML = '<div class="message error">⚠️ ' + (data.message || '로그인 실패') + '</div>';
                    loginButton.disabled = false;
                    spinner.classList.remove('active');
                }
            } catch (error) {
                messageArea.innerHTML = '<div class="message error">⚠️ 네트워크 오류: ' + error.message + '</div>';
                loginButton.disabled = false;
                spinner.classList.remove('active');
            }
        });
    </script>
</body>
</html>
                """,
                errorMessage != null ? "<div class=\"message error\">⚠️ 로그인 실패: 사용자명 또는 비밀번호를 확인하세요.</div>" : "",
                logoutMessage != null ? "<div class=\"message success\">✅ 로그아웃되었습니다.</div>" : "",
                usernameParam,
                passwordParam,
                loginProcessingUrl,
                usernameParam,
                passwordParam
        );

        writer.write(html);
        writer.flush();

        log.debug("Generated default primary REST login page for MFA flow. Processing URL: {}", loginProcessingUrl);
    }

    /**
     * OTT Request Code Page 생성
     */
    private void generateOttRequestCodePage(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter writer = response.getWriter();

        String ottChallengeUrl = extractOttChallengeUrl(); // DSL 설정 기반으로 변경

        String html = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MFA - 인증 코드 요청</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 480px; margin: 50px auto; background: white; padding: 32px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        h1 { margin: 0 0 16px; font-size: 24px; color: #333; }
        p { color: #666; margin-bottom: 24px; }
        button { width: 100%%; padding: 14px; background: #007bff; color: white; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }
        button:disabled { background: #6c757d; cursor: not-allowed; }
    </style>
    <script src="/js/contexa-mfa-sdk.js"></script>
</head>
<body>
    <div class="container">
        <h1>인증 코드 요청</h1>
        <p>등록된 이메일 주소로 인증 코드를 전송합니다.</p>
        <button id="request-button" onclick="requestCode()">인증 코드 전송</button>
    </div>

    <script>
        async function requestCode() {
            const button = document.getElementById('request-button');
            button.disabled = true;
            button.textContent = '전송 중...';

            try {
                const mfa = new ContexaMFA.Client({ autoRedirect: true });
                await mfa.init();
                await mfa.apiClient.requestOttCode();

                alert('인증 코드가 전송되었습니다.');
                window.location.href = '%s';
            } catch (error) {
                alert('전송 실패: ' + error.message);
                button.disabled = false;
                button.textContent = '인증 코드 전송';
            }
        }
    </script>
</body>
</html>
                """.formatted(ottChallengeUrl);

        writer.write(html);
        writer.flush();
    }

    /**
     * OTT Verify Page 생성
     */
    private void generateOttVerifyPage(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter writer = response.getWriter();

        String html = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MFA - 인증 코드 입력</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 480px; margin: 50px auto; background: white; padding: 32px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        h1 { margin: 0 0 16px; font-size: 24px; color: #333; }
        input { width: 100%%; padding: 14px; margin-bottom: 16px; border: 1px solid #ddd; border-radius: 6px; font-size: 18px; text-align: center; letter-spacing: 0.5em; box-sizing: border-box; }
        button { width: 100%%; padding: 14px; margin-bottom: 8px; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }
        .btn-primary { background: #007bff; color: white; }
        .btn-secondary { background: #6c757d; color: white; }
        button:disabled { opacity: 0.6; cursor: not-allowed; }
    </style>
    <script src="/js/contexa-mfa-sdk.js"></script>
</head>
<body>
    <div class="container">
        <h1>인증 코드 입력</h1>
        <form id="verify-form" onsubmit="verifyCode(event)">
            <input type="text" id="code-input" placeholder="6자리 코드 입력" maxlength="6" required autofocus />
            <button type="submit" class="btn-primary" id="verify-button">확인</button>
            <button type="button" class="btn-secondary" onclick="resendCode()">코드 재전송</button>
        </form>
    </div>

    <script>
        const mfa = new ContexaMFA.Client({ autoRedirect: true });

        async function verifyCode(event) {
            event.preventDefault();
            const button = document.getElementById('verify-button');
            const input = document.getElementById('code-input');

            button.disabled = true;
            button.textContent = '확인 중...';

            try {
                await mfa.verifyOtt(input.value);
            } catch (error) {
                alert('인증 실패: ' + error.message);
                button.disabled = false;
                button.textContent = '확인';
                input.value = '';
            }
        }

        async function resendCode() {
            try {
                await mfa.apiClient.requestOttCode();
                alert('인증 코드가 재전송되었습니다.');
            } catch (error) {
                alert('재전송 실패: ' + error.message);
            }
        }
    </script>
</body>
</html>
                """;

        writer.write(html);
        writer.flush();
    }

    /**
     * Passkey Challenge Page 생성
     */
    private void generatePasskeyChallengePage(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter writer = response.getWriter();

        String html = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MFA - Passkey 인증</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 480px; margin: 50px auto; background: white; padding: 32px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); text-align: center; }
        h1 { margin: 0 0 16px; font-size: 24px; color: #333; }
        p { color: #666; margin-bottom: 24px; }
        button { width: 100%%; padding: 14px; background: #007bff; color: white; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }
        button:disabled { background: #6c757d; cursor: not-allowed; }
    </style>
    <script src="/js/contexa-mfa-sdk.js"></script>
</head>
<body>
    <div class="container">
        <h1>🔐 Passkey 인증</h1>
        <p>생체 인증 또는 보안 키를 사용하여 인증하세요.</p>
        <button id="auth-button" onclick="authenticate()">Passkey 인증 시작</button>
    </div>

    <script>
        window.onload = function() {
            // 페이지 로드 시 자동으로 인증 시작
            authenticate();
        };

        async function authenticate() {
            const button = document.getElementById('auth-button');
            button.disabled = true;
            button.textContent = '인증 진행 중...';

            try {
                const mfa = new ContexaMFA.Client({ autoRedirect: true });
                await mfa.init();
                await mfa.verifyPasskey();
            } catch (error) {
                alert('인증 실패: ' + error.message);
                button.disabled = false;
                button.textContent = 'Passkey 인증 시작';
            }
        }
    </script>
</body>
</html>
                """;

        writer.write(html);
        writer.flush();
    }

    /**
     * Configure Page 생성
     */
    private void generateConfigurePage(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter writer = response.getWriter();

        String html = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MFA - 초기 설정</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 600px; margin: 50px auto; background: white; padding: 32px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        h1 { margin: 0 0 16px; font-size: 24px; color: #333; }
        p { color: #666; margin-bottom: 24px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>MFA 초기 설정</h1>
        <p>다단계 인증을 설정하여 계정을 보호하세요.</p>
        <p>이 페이지는 기본 페이지입니다. 커스텀 MFA 설정 페이지를 구현하세요.</p>
    </div>
</body>
</html>
                """;

        writer.write(html);
        writer.flush();
    }

    /**
     * Failure Page 생성
     */
    private void generateFailurePage(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter writer = response.getWriter();

        String errorMessage = request.getParameter("error");
        String displayMessage = StringUtils.hasText(errorMessage) ? errorMessage : "인증에 실패했습니다.";

        String selectFactorUrl = extractSelectFactorUrl(); // DSL 설정 기반으로 변경

        String html = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MFA - 인증 실패</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 480px; margin: 50px auto; background: white; padding: 32px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); text-align: center; }
        h1 { margin: 0 0 16px; font-size: 24px; color: #dc3545; }
        p { color: #666; margin-bottom: 24px; }
        button { padding: 14px 32px; background: #007bff; color: white; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚠️ 인증 실패</h1>
        <p>%s</p>
        <button onclick="location.href='%s'">다시 시도</button>
    </div>
</body>
</html>
                """.formatted(displayMessage, selectFactorUrl);

        writer.write(html);
        writer.flush();
    }
}
