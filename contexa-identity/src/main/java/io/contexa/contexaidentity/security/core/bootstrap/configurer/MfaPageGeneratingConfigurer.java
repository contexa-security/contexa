package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexaidentity.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.exceptionhandling.MfaAuthenticationEntryPoint;
import io.contexa.contexaidentity.security.filter.DefaultMfaPageGeneratingFilter;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexacommon.properties.MfaPageConfig;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.*;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

import java.util.Arrays;
import java.util.Collections;

/**
 * MFA Page Generating Configurer
 *
 * DefaultMfaPageGeneratingFilter를 SecurityFilterChain에 등록하여
 * MFA 플로우의 모든 페이지들을 DSL 설정 기반으로 동적 생성합니다.
 *
 * 페이지 생성 범위:
 * 1. Primary Authentication (1차 인증) - Form Login 페이지
 * 2. MFA Select Factor (2차 인증 선택) - Factor 선택 페이지
 * 3. Factor Challenge (개별 Factor 챌린지) - OTT, Passkey 등
 *
 * 이 Configurer는 MFA 플로우가 설정된 경우에만 필터를 등록하며,
 * AuthenticationFlowConfig의 DSL 설정을 기반으로 페이지를 생성합니다.
 *
 * 커스텀 페이지 지원:
 * - Primary Auth: FormOptions.loginPage()
 * - MFA Pages: MfaPageConfig (selectFactorPage, ottPages, passkeyPages 등)
 *
 * Spring Component로 등록되어 DefaultSecurityConfigurerProvider에 의해 자동으로 수집됩니다.
 *
 * @see DefaultMfaPageGeneratingFilter
 * @see AuthenticationFlowConfig
 * @see MfaPageConfig
 */
@Slf4j
public class MfaPageGeneratingConfigurer implements SecurityConfigurer {

    private final ApplicationContext applicationContext;

    public MfaPageGeneratingConfigurer(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Override
    public void init(PlatformContext platformContext, PlatformConfig config) {
        log.info("🔧 MfaPageGeneratingConfigurer initialized by Platform.");

        // MFA 플로우가 있는지 확인
        boolean hasMfaFlow = config.getFlows().stream()
                .anyMatch(flow -> AuthType.MFA.name().equalsIgnoreCase(flow.getTypeName()));

        if (hasMfaFlow) {
            log.info("MFA flow detected. DefaultMfaPageGeneratingFilter will be registered in configure() phase.");
        } else {
            log.info("No MFA flow detected. DefaultMfaPageGeneratingFilter will not be registered.");
        }
    }

    @Override
    public void configure(FlowContext flowContext) {
        AuthenticationFlowConfig flowConfig = flowContext.flow();

        // MFA 플로우에만 필터를 추가
        if (!AuthType.MFA.name().equalsIgnoreCase(flowConfig.getTypeName())) {
            log.debug("Skipping MfaPageGeneratingFilter for non-MFA flow: {}", flowConfig.getTypeName());
            return;
        }

        log.info("🔧 Configuring DefaultMfaPageGeneratingFilter for MFA flow: {}", flowConfig.getTypeName());

        try {
            // 필수 의존성 가져오기
            MfaStateMachineIntegrator stateMachineIntegrator =
                    applicationContext.getBean(MfaStateMachineIntegrator.class);
            AuthUrlProvider authUrlProvider =
                    applicationContext.getBean(AuthUrlProvider.class);

            DefaultMfaPageGeneratingFilter mfaPageFilter = new DefaultMfaPageGeneratingFilter(
                    flowConfig,              // DSL 설정 전체 전달
                    stateMachineIntegrator,
                    authUrlProvider          // URL 우선순위 로직 제공
            );

            // ⭐ Spring Security FormLoginConfigurer 패턴: SharedObject로 등록
            flowContext.http().setSharedObject(DefaultMfaPageGeneratingFilter.class, mfaPageFilter);

            // HttpSecurity에 필터 추가 (UsernamePasswordAuthenticationFilter 이전에 삽입)
            flowContext.http().addFilterBefore(
                    mfaPageFilter,
                    UsernamePasswordAuthenticationFilter.class
            );

            // ⭐ MfaAuthenticationEntryPoint 등록 (Spring Security AbstractAuthenticationFilterConfigurer 패턴)
            registerMfaAuthenticationEntryPoint(flowContext, flowConfig);

            // 로깅: 생성될 페이지 URL 정보
            String primaryLoginPage = extractPrimaryLoginPage(flowConfig);
            String selectFactorPage = extractSelectFactorUrl(flowConfig);
            String customPagesInfo = buildCustomPagesInfo(flowConfig);

            log.info("DefaultMfaPageGeneratingFilter successfully registered for MFA flow.");
            log.info("   Primary authentication page: {}", primaryLoginPage);
            log.info("   Select factor page: {}", selectFactorPage);
            if (StringUtils.hasText(customPagesInfo)) {
                log.info("   Custom pages configured: {}", customPagesInfo);
            }

        } catch (Exception e) {
            log.error(" CRITICAL: Failed to register DefaultMfaPageGeneratingFilter for MFA flow", e);
            throw new RuntimeException("Failed to configure MFA Page Generating Filter", e);
        }
    }

    @Override
    public int getOrder() {
        // GlobalConfigurer 이후, Feature Adapter들 이전에 실행
        return SecurityConfigurer.HIGHEST_PRECEDENCE + 150;
    }

    // ===== Helper Methods =====

    /**
     * MfaAuthenticationEntryPoint 등록
     *
     * Spring Security의 AbstractAuthenticationFilterConfigurer.registerDefaultAuthenticationEntryPoint() 패턴을 따릅니다.
     * AuthenticationFlowConfig에서 생성된 EntryPoint를 HttpSecurity에 기본 EntryPoint로 등록합니다.
     *
     * @param flowContext 플로우 컨텍스트
     * @param flowConfig MFA 플로우 설정
     */
    private void registerMfaAuthenticationEntryPoint(FlowContext flowContext, AuthenticationFlowConfig flowConfig) {
        MfaAuthenticationEntryPoint entryPoint = flowConfig.getMfaAuthenticationEntryPoint();

        // ⭐ EntryPoint가 null이면 예외 (MFA는 EntryPoint 필수)
        if (entryPoint == null) {
            throw new IllegalStateException(
                "MfaAuthenticationEntryPoint is required for MFA flow but was null in flowConfig [" +
                flowConfig.getTypeName() + "]. " +
                "This indicates a configuration error in MfaDslConfigurerImpl. " +
                "Check that primaryAuthenticationOptions is properly configured and EntryPoint is created in build() method."
            );
        }

        try {
            // ExceptionHandlingConfigurer 가져오기 (타입 안전성 경고 억제)
            ExceptionHandlingConfigurer<HttpSecurity> exceptionHandling =
                    (ExceptionHandlingConfigurer<HttpSecurity>)
                    flowContext.http().getConfigurer(ExceptionHandlingConfigurer.class);

            // ⭐ ExceptionHandlingConfigurer가 null이면 예외 (MFA는 EntryPoint 등록 필수)
            if (exceptionHandling == null) {
                throw new IllegalStateException(
                    "ExceptionHandlingConfigurer not found in HttpSecurity for MFA flow [" +
                    flowConfig.getTypeName() + "]. " +
                    "This indicates a Spring Security configuration issue. " +
                    "Ensure HttpSecurity is properly initialized with exception handling support."
                );
            }

            // RequestMatcher 생성 (HTML 요청만 매칭)
            RequestMatcher entryPointMatcher = createMfaEntryPointMatcher(flowContext);

            // 기본 EntryPoint로 등록 (Spring Security FormLoginConfigurer 패턴)
            exceptionHandling.defaultAuthenticationEntryPointFor(entryPoint, entryPointMatcher);

            log.info("MfaAuthenticationEntryPoint registered for HTML requests with loginPage: {}",
                    entryPoint.getLoginFormUrl());

        } catch (Exception e) {
            log.error(" Failed to register MfaAuthenticationEntryPoint", e);
            throw new RuntimeException("Failed to register MFA AuthenticationEntryPoint", e);
        }
    }

    /**
     * MFA EntryPoint RequestMatcher 생성
     *
     * Spring Security의 AbstractAuthenticationFilterConfigurer.getAuthenticationEntryPointMatcher() 패턴을 따릅니다.
     * HTML/XHTML/TEXT 요청이면서 AJAX가 아닌 요청만 매칭합니다.
     *
     * @param flowContext 플로우 컨텍스트
     * @return HTML 요청 매처
     */
    private RequestMatcher createMfaEntryPointMatcher(FlowContext flowContext) {
        // ContentNegotiationStrategy 가져오기
        ContentNegotiationStrategy contentNegotiationStrategy =
                flowContext.http().getSharedObject(ContentNegotiationStrategy.class);

        if (contentNegotiationStrategy == null) {
            contentNegotiationStrategy = new HeaderContentNegotiationStrategy();
        }

        // HTML/XHTML/TEXT/IMAGE 요청 매칭
        MediaTypeRequestMatcher mediaMatcher = new MediaTypeRequestMatcher(
                contentNegotiationStrategy,
                MediaType.APPLICATION_XHTML_XML,
                new MediaType("image", "*"),
                MediaType.TEXT_HTML,
                MediaType.TEXT_PLAIN
        );
        mediaMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));

        // AJAX 요청 제외 (X-Requested-With 헤더가 없는 것만)
        RequestMatcher notXRequestedWith = new NegatedRequestMatcher(
                new RequestHeaderRequestMatcher("X-Requested-With", "XMLHttpRequest")
        );

        // 두 조건을 AND로 결합
        return new AndRequestMatcher(Arrays.asList(notXRequestedWith, mediaMatcher));
    }


    /**
     * Primary Login Page URL 추출
     */
    private String extractPrimaryLoginPage(AuthenticationFlowConfig flowConfig) {
        PrimaryAuthenticationOptions primaryOpts = flowConfig.getPrimaryAuthenticationOptions();
        if (primaryOpts != null) {
            // Form 인증인 경우
            if (primaryOpts.isFormLogin()) {
                FormOptions formOpts = primaryOpts.getFormOptions();
                return StringUtils.hasText(formOpts.getLoginPage()) ?
                        formOpts.getLoginPage() : "/loginForm (default)";
            }

            // REST 인증인 경우
            if (primaryOpts.isRestLogin()) {
                String loginPage = primaryOpts.getLoginPage();
                return StringUtils.hasText(loginPage) ? loginPage : "/loginForm (default)";
            }
        }
        return "/loginForm (default)";
    }

    /**
     * Select Factor URL 추출
     */
    private String extractSelectFactorUrl(AuthenticationFlowConfig flowConfig) {
        MfaPageConfig pageConfig = flowConfig.getMfaPageConfig();
        if (pageConfig != null && StringUtils.hasText(pageConfig.getSelectFactorPageUrl())) {
            return pageConfig.getSelectFactorPageUrl();
        }
        return "/mfa/select-factor (default)";
    }

    /**
     * 커스텀 페이지 정보 빌드
     */
    private String buildCustomPagesInfo(AuthenticationFlowConfig flowConfig) {
        MfaPageConfig pageConfig = flowConfig.getMfaPageConfig();
        if (pageConfig == null) {
            return "";
        }

        StringBuilder info = new StringBuilder();

        if (pageConfig.hasCustomSelectFactorPage()) {
            info.append("selectFactor=").append(pageConfig.getSelectFactorPageUrl()).append(", ");
        }
        if (pageConfig.hasCustomOttRequestPage()) {
            info.append("ottRequest=").append(pageConfig.getOttRequestPageUrl()).append(", ");
        }
        if (pageConfig.hasCustomOttVerifyPage()) {
            info.append("ottVerify=").append(pageConfig.getOttVerifyPageUrl()).append(", ");
        }
        if (pageConfig.hasCustomPasskeyPage()) {
            info.append("passkey=").append(pageConfig.getPasskeyChallengePageUrl()).append(", ");
        }
        if (pageConfig.hasCustomConfigurePage()) {
            info.append("configure=").append(pageConfig.getConfigurePageUrl()).append(", ");
        }
        if (pageConfig.hasCustomFailurePage()) {
            info.append("failure=").append(pageConfig.getFailurePageUrl());
        }

        String result = info.toString();
        return result.endsWith(", ") ? result.substring(0, result.length() - 2) : result;
    }
}
