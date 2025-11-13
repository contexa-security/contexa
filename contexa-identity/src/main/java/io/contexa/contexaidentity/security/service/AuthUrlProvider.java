package io.contexa.contexaidentity.security.service;

import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.core.dsl.option.OttOptions;
import io.contexa.contexaidentity.security.core.dsl.option.PasskeyOptions;
import io.contexa.contexaidentity.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.properties.MfaPageConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import jakarta.annotation.PostConstruct;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * 중앙 집중식 인증 URL 제공 서비스
 * <p>
 * 모든 필터, Configurer, 컨트롤러는 이 서비스를 통해 URL에 접근해야 함.
 * 직접적인 AuthContextProperties 접근은 지양.
 * <p>
 * 기능:
 * <ul>
 *   <li>타입 안전한 URL 접근 메서드 제공</li>
 *   <li>URL 중복 검증</li>
 *   <li>URL 형식 검증</li>
 *   <li>집계 메서드 (필터, SDK용)</li>
 *   <li>MFA 커스텀 페이지 설정 지원 (DSL .mfaPage() 설정)</li>
 * </ul>
 *
 * @since 2025-01
 */
@Slf4j
@Service
public class AuthUrlProvider {

    private final AuthContextProperties properties;
    private MfaPageConfig mfaPageConfig = new MfaPageConfig();

    /**
     * Factor Options 저장소 (DSL에서 설정한 커스텀 URL 정보)
     * Key: AuthType (OTT, PASSKEY 등)
     * Value: AuthenticationProcessingOptions (OttOptions, PasskeyOptions 등)
     */
    private final Map<AuthType, AuthenticationProcessingOptions> factorOptionsMap = new HashMap<>();

    /**
     * P0.4: Primary Authentication Options 저장소 (MFA 1차 인증 설정)
     */
    private PrimaryAuthenticationOptions primaryAuthOptions;

    /**
     * Constructor
     *
     * @param properties 인증 URL 설정
     */
    public AuthUrlProvider(AuthContextProperties properties) {
        this.properties = properties;
    }

    /**
     * P0.4: Primary Authentication Options 설정
     *
     * <p>
     * MfaAuthenticationAdapter에서 AuthenticationFlowConfig.getPrimaryAuthenticationOptions()를 가져와서 주입합니다.
     * </p>
     *
     * @param primaryAuthOptions Primary 인증 옵션 (null 허용)
     */
    public void setPrimaryAuthenticationOptions(@Nullable PrimaryAuthenticationOptions primaryAuthOptions) {
        if (primaryAuthOptions != null) {
            log.info("📋 Primary Authentication Options 설정:");
            log.debug("  [변경 전] Form Login Processing: {}", getPrimaryFormLoginProcessing());
            log.debug("  [변경 전] Login Page: {}", getPrimaryLoginPage());
            log.debug("  [변경 전] Login Failure: {}", getPrimaryLoginFailure());

            this.primaryAuthOptions = primaryAuthOptions;

            log.info("✅ Primary authentication options set: loginPage={}, failureUrl={}, loginProcessingUrl={}",
                primaryAuthOptions.getLoginPage(),
                primaryAuthOptions.getFailureUrl(),
                primaryAuthOptions.getLoginProcessingUrl());

            log.debug("  [변경 후] Form Login Processing: {}", getPrimaryFormLoginProcessing());
            log.debug("  [변경 후] Login Page: {}", getPrimaryLoginPage());
            log.debug("  [변경 후] Login Failure: {}", getPrimaryLoginFailure());
        }
    }

    /**
     * MFA 커스텀 페이지 설정 (DSL .mfaPage()로 설정된 값 주입)
     *
     * SecurityConfigurer에서 AuthenticationFlowConfig.getMfaPageConfig()를 가져와서 설정합니다.
     *
     * @param mfaPageConfig MFA 커스텀 페이지 설정 (null 허용)
     */
    public void setMfaPageConfig(@Nullable MfaPageConfig mfaPageConfig) {
        if (mfaPageConfig != null) {
            this.mfaPageConfig = mfaPageConfig;
            log.info("MFA custom page configuration applied to AuthUrlProvider: {}", mfaPageConfig);
        }
    }

    /**
     * Factor Options 업데이트 (DSL에서 설정한 커스텀 URL 주입)
     *
     * <p>
     * MfaAuthenticationAdapter에서 AuthenticationFlowConfig.getRegisteredFactorOptions()를 가져와서 주입합니다.
     * 이 메서드를 통해 OttOptions, PasskeyOptions 등의 커스텀 URL 설정이 AuthUrlProvider에 반영됩니다.
     * </p>
     *
     * <p>
     * 우선순위: DSL Factor Options > AuthContextProperties > 기본값
     * </p>
     *
     * @param options Factor Options Map (null 허용)
     */
    public void updateFactorOptions(@Nullable Map<AuthType, AuthenticationProcessingOptions> options) {
        if (options != null && !options.isEmpty()) {
            // P1.3: 업데이트 전 기존 URL 로깅
            log.info("📋 Factor Options 업데이트 시작:");
            log.debug("  [변경 전] OTT Code Generation: {}", getOttCodeGeneration());
            log.debug("  [변경 전] OTT Login Processing: {}", getOttLoginProcessing());
            log.debug("  [변경 전] Passkey Login Processing: {}", getPasskeyLoginProcessing());

            this.factorOptionsMap.putAll(options);
            log.info("✅ Factor options updated in AuthUrlProvider: {}", options.keySet());

            // P1.3: 업데이트 후 새 URL 로깅
            options.forEach((authType, opts) -> {
                if (opts instanceof OttOptions ottOpts) {
                    log.info("  - OTT: tokenGeneratingUrl={}, loginProcessing={}",
                        ottOpts.getTokenGeneratingUrl(), ottOpts.getLoginProcessingUrl());
                } else if (opts instanceof PasskeyOptions passkeyOpts) {
                    log.info("  - Passkey: loginProcessing={}",
                        passkeyOpts.getLoginProcessingUrl());
                }
            });

            log.debug("  [변경 후] OTT Code Generation: {}", getOttCodeGeneration());
            log.debug("  [변경 후] OTT Login Processing: {}", getOttLoginProcessing());
            log.debug("  [변경 후] Passkey Login Processing: {}", getPasskeyLoginProcessing());
        } else {
            log.debug("No factor options to update (null or empty)");
        }
    }

    // ========================================
    // Primary Authentication URLs
    // ========================================

    /**
     * Form 로그인 처리 URL
     *
     * <p>
     * 우선순위:
     * 1. PrimaryAuthenticationOptions.loginProcessingUrl (MFA 1차 인증 DSL 설정)
     * 2. AuthContextProperties 기본값 (/login)
     * </p>
     *
     * @return POST /login (기본값)
     */
    public String getPrimaryFormLoginProcessing() {
        if (primaryAuthOptions != null && StringUtils.hasText(primaryAuthOptions.getLoginProcessingUrl())) {
            if (primaryAuthOptions.isFormLogin()) {
                return primaryAuthOptions.getLoginProcessingUrl();
            }
        }
        return properties.getUrls().getPrimary().getFormLoginProcessing();
    }

    /**
     * REST API 로그인 처리 URL
     *
     * <p>
     * 우선순위:
     * 1. PrimaryAuthenticationOptions.loginProcessingUrl (MFA 1차 인증 DSL 설정, REST 타입)
     * 2. AuthContextProperties 기본값 (/api/auth/login)
     * </p>
     *
     * @return POST /api/auth/login (기본값)
     */
    public String getPrimaryRestLoginProcessing() {
        if (primaryAuthOptions != null && StringUtils.hasText(primaryAuthOptions.getLoginProcessingUrl())) {
            if (primaryAuthOptions.isRestLogin()) {
                return primaryAuthOptions.getLoginProcessingUrl();
            }
        }
        return properties.getUrls().getPrimary().getRestLoginProcessing();
    }

    /**
     * 로그인 페이지 URL
     *
     * <p>
     * 우선순위:
     * 1. PrimaryAuthenticationOptions.loginPage (MFA 1차 인증 DSL 설정)
     * 2. AuthContextProperties 기본값 (/loginForm)
     * </p>
     *
     * @return GET /loginForm (기본값)
     */
    public String getPrimaryLoginPage() {
        if (primaryAuthOptions != null && StringUtils.hasText(primaryAuthOptions.getLoginPage())) {
            return primaryAuthOptions.getLoginPage();
        }
        return properties.getUrls().getPrimary().getFormLoginPage();
    }

    /**
     * 로그인 실패 URL
     *
     * <p>
     * 우선순위:
     * 1. PrimaryAuthenticationOptions.failureUrl (MFA 1차 인증 DSL 설정)
     * 2. AuthContextProperties 기본값 (/login?error)
     * </p>
     *
     * @return /login?error (기본값)
     */
    public String getPrimaryLoginFailure() {
        if (primaryAuthOptions != null && StringUtils.hasText(primaryAuthOptions.getFailureUrl())) {
            return primaryAuthOptions.getFailureUrl();
        }
        return properties.getUrls().getPrimary().getLoginFailure();
    }

    /**
     * 로그인 성공 URL
     * @return /home (기본값)
     */
    public String getPrimaryLoginSuccess() {
        return properties.getUrls().getPrimary().getLoginSuccess();
    }

    /**
     * 로그아웃 페이지 URL
     * @return /logout (기본값)
     */
    public String getLogoutPage() {
        return properties.getUrls().getPrimary().getLogoutPage();
    }

    // ========================================
    // Single Authentication URLs (MFA 없는 독립 인증)
    // ========================================

    /**
     * 단일 Form 로그인 처리 URL
     * @return POST /login (Spring Security 기본값)
     */
    public String getSingleFormLoginProcessing() {
        return properties.getUrls().getSingle().getFormLoginProcessing();
    }

    /**
     * 단일 Form 로그인 페이지 URL
     * @return GET /login (Spring Security 기본값)
     */
    public String getSingleFormLoginPage() {
        return properties.getUrls().getSingle().getFormLoginPage();
    }

    /**
     * 단일 REST API 로그인 처리 URL
     * @return POST /api/auth/login (기본값)
     */
    public String getSingleRestLoginProcessing() {
        return properties.getUrls().getSingle().getRestLoginProcessing();
    }

    /**
     * 단일 로그인 실패 URL
     * @return /login?error (기본값)
     */
    public String getSingleLoginFailure() {
        return properties.getUrls().getSingle().getLoginFailure();
    }

    /**
     * 단일 로그인 성공 URL
     * @return / (기본값)
     */
    public String getSingleLoginSuccess() {
        return properties.getUrls().getSingle().getLoginSuccess();
    }

    /**
     * 단일 OTT 이메일 요청 페이지
     * @return GET /login/ott (기본값)
     */
    public String getSingleOttRequestEmail() {
        return properties.getUrls().getSingle().getOtt().getRequestEmail();
    }

    /**
     * 단일 OTT 코드 생성 URL
     * @return POST /login/ott/generate (기본값)
     */
    public String getSingleOttCodeGeneration() {
        return properties.getUrls().getSingle().getOtt().getCodeGeneration();
    }

    /**
     * 단일 OTT 코드 전송 완료 페이지
     * @return GET /login/ott/sent (기본값)
     */
    public String getSingleOttCodeSent() {
        return properties.getUrls().getSingle().getOtt().getCodeSent();
    }

    /**
     * 단일 OTT 챌린지 페이지
     * @return GET /login/ott/verify (기본값)
     */
    public String getSingleOttChallenge() {
        return properties.getUrls().getSingle().getOtt().getChallenge();
    }

    /**
     * 단일 OTT 로그인 처리 URL
     * @return POST /login/ott (Spring Security OneTimeTokenLogin 기본값)
     */
    public String getSingleOttLoginProcessing() {
        return properties.getUrls().getSingle().getOtt().getLoginProcessing();
    }

    /**
     * 단일 OTT 코드 전송 완료 페이지
     * @return GET /ott/sent (기본값)
     */
    public String getSingleOttSent() {
        return properties.getUrls().getFactors().getOtt().getSingleOttSent();
    }

    /**
     * 단일 OTT 로그인 실패 URL
     * @return /login/ott?error (기본값)
     */
    public String getSingleOttLoginFailure() {
        return properties.getUrls().getSingle().getOtt().getLoginFailure();
    }

    /**
     * 단일 Passkey 로그인 페이지
     * @return GET /login/webauthn (기본값)
     */
    public String getSinglePasskeyLoginPage() {
        return properties.getUrls().getSingle().getPasskey().getLoginPage();
    }

    /**
     * 단일 Passkey 로그인 처리 URL
     * @return POST /login/webauthn (Spring Security WebAuthn 기본값)
     */
    public String getSinglePasskeyLoginProcessing() {
        return properties.getUrls().getSingle().getPasskey().getLoginProcessing();
    }

    /**
     * 단일 Passkey 로그인 실패 URL
     * @return /login/webauthn?error (기본값)
     */
    public String getSinglePasskeyLoginFailure() {
        return properties.getUrls().getSingle().getPasskey().getLoginFailure();
    }

    /**
     * 단일 Passkey Assertion Options URL (Spring Security 표준)
     * @return /webauthn/authenticate/options (Spring Security 기본값)
     */
    public String getSinglePasskeyAssertionOptions() {
        return properties.getUrls().getSingle().getPasskey().getAssertionOptions();
    }

    /**
     * 단일 Passkey Registration Options URL (Spring Security 표준)
     * @return /webauthn/registration/options (Spring Security 기본값)
     */
    public String getSinglePasskeyRegistrationOptions() {
        return properties.getUrls().getSingle().getPasskey().getRegistrationOptions();
    }

    /**
     * 단일 Passkey 등록 요청 URL
     * @return POST /passkey/register-request (기본값)
     */
    public String getSinglePasskeyRegistrationRequest() {
        return properties.getUrls().getSingle().getPasskey().getRegistrationRequest();
    }

    /**
     * 단일 Passkey 등록 처리 URL
     * @return POST /webauthn/register (기본값)
     */
    public String getSinglePasskeyRegistrationProcessing() {
        return properties.getUrls().getSingle().getPasskey().getRegistrationProcessing();
    }

    // ========================================
    // MFA Lifecycle URLs
    // ========================================

    /**
     * MFA 시작 URL
     * @return GET /mfa/initiate (기본값)
     */
    public String getMfaInitiate() {
        return properties.getUrls().getMfa().getInitiate();
    }

    /**
     * MFA 설정 URL
     *
     * <p>
     * 우선순위:
     * 1. MfaPageConfig.configurePageUrl (DSL 커스텀 설정)
     * 2. AuthContextProperties 기본값 (/mfa/configure)
     * </p>
     *
     * @return MFA 설정 페이지 URL
     */
    public String getMfaConfigure() {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomConfigurePage()) {
            return mfaPageConfig.getConfigurePageUrl();
        }
        return properties.getUrls().getMfa().getConfigure();
    }

    /**
     * Factor 선택 URL (GET: 페이지, POST: API 처리)
     *
     * <p>
     * 우선순위:
     * 1. MfaPageConfig.selectFactorPageUrl (DSL 커스텀 설정)
     * 2. AuthContextProperties 기본값 (/mfa/select-factor)
     * </p>
     *
     * @return Factor 선택 페이지 URL
     */
    public String getMfaSelectFactor() {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomSelectFactorPage()) {
            return mfaPageConfig.getSelectFactorPageUrl();
        }
        return properties.getUrls().getMfa().getSelectFactor();
    }

    /**
     * MFA 성공 리다이렉트 URL
     * @return /home (기본값)
     */
    public String getMfaSuccess() {
        return properties.getUrls().getMfa().getSuccess();
    }

    /**
     * MFA 실패 페이지 URL
     *
     * <p>
     * 우선순위:
     * 1. MfaPageConfig.failurePageUrl (DSL 커스텀 설정)
     * 2. AuthContextProperties 기본값 (/mfa/failure)
     * </p>
     *
     * @return MFA 실패 페이지 URL
     */
    public String getMfaFailure() {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomFailurePage()) {
            return mfaPageConfig.getFailurePageUrl();
        }
        return properties.getUrls().getMfa().getFailure();
    }

    /**
     * MFA 취소 URL (POST)
     * @return /mfa/cancel (기본값)
     */
    public String getMfaCancel() {
        return properties.getUrls().getMfa().getCancel();
    }

    /**
     * MFA 취소 리다이렉트 URL (로그인 페이지)
     * @return /loginForm (기본값)
     */
    public String getMfaCancelRedirect() {
        return properties.getUrls().getMfa().getCancelRedirect();
    }

    /**
     * MFA 상태 조회 URL
     * @return /mfa/status (기본값)
     */
    public String getMfaStatus() {
        return properties.getUrls().getMfa().getStatus();
    }

    /**
     * MFA Context 조회 URL
     * @return /mfa/context (기본값)
     */
    public String getMfaContext() {
        return properties.getUrls().getMfa().getContext();
    }

    /**
     * OTT 코드 재전송 요청 URL
     * @return /mfa/request-ott-code (기본값)
     */
    public String getMfaRequestOttCode() {
        return properties.getUrls().getMfa().getRequestOttCode();
    }

    /**
     * SDK 설정 조회 URL
     * @return /api/mfa/config (기본값)
     */
    public String getMfaConfig() {
        return properties.getUrls().getMfa().getConfig();
    }

    // ========================================
    // OTT Factor URLs
    // ========================================

    /**
     * OTT 코드 요청 UI 페이지 (이메일 입력)
     *
     * <p>
     * 우선순위:
     * 1. MfaPageConfig.ottRequestPageUrl (DSL 커스텀 설정)
     * 2. AuthContextProperties 기본값 (/mfa/ott/request-code-ui)
     * </p>
     *
     * @return OTT 코드 요청 페이지 URL
     */
    public String getOttRequestCodeUi() {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomOttRequestPage()) {
            return mfaPageConfig.getOttRequestPageUrl();
        }
        return properties.getUrls().getFactors().getOtt().getRequestCodeUi();
    }

    /**
     * OTT 코드 생성 URL
     *
     * <p>
     * 우선순위:
     * 1. OttOptions.tokenGeneratingUrl (DSL 커스텀 설정)
     * 2. AuthContextProperties 기본값 (/mfa/ott/generate-code)
     * </p>
     *
     * @return POST /mfa/ott/generate-code (기본값)
     */
    public String getOttCodeGeneration() {
        AuthenticationProcessingOptions ottOpts = factorOptionsMap.get(AuthType.OTT);
        if (ottOpts instanceof OttOptions ottOptions) {
            String customUrl = ottOptions.getTokenGeneratingUrl();
            if (StringUtils.hasText(customUrl)) {
                return customUrl;
            }
        }

        return properties.getUrls().getFactors().getOtt().getCodeGeneration();
    }

    /**
     * OTT 코드 전송 완료 페이지
     * @return GET /mfa/ott/code-sent (기본값)
     */
    public String getOttCodeSent() {
        return properties.getUrls().getFactors().getOtt().getCodeSent();
    }

    /**
     * OTT 코드 입력 챌린지 UI
     *
     * <p>
     * 우선순위:
     * 1. OttOptions.defaultSubmitPageUrl (DSL 커스텀 설정 - API URL)
     * 2. MfaPageConfig.ottVerifyPageUrl (DSL 커스텀 설정 - UI 페이지)
     * 3. AuthContextProperties 기본값 (/mfa/challenge/ott)
     * </p>
     *
     * @return OTT 코드 검증 챌린지 페이지 URL
     */
    public String getOttChallengeUi() {
        AuthenticationProcessingOptions ottOpts = factorOptionsMap.get(AuthType.OTT);
        if (ottOpts instanceof OttOptions ottOptions) {
            String customUrl = ottOptions.getDefaultSubmitPageUrl();
            if (StringUtils.hasText(customUrl)) {
                return customUrl;
            }
        }

        if (mfaPageConfig != null && mfaPageConfig.hasCustomOttVerifyPage()) {
            return mfaPageConfig.getOttVerifyPageUrl();
        }

        return properties.getUrls().getFactors().getOtt().getChallengeUi();
    }

    /**
     * OTT 코드 검증 처리 URL (Filter가 처리)
     *
     * <p>
     * 우선순위:
     * 1. OttOptions.loginProcessingUrl (DSL 커스텀 설정)
     * 2. AuthContextProperties 기본값 (/login/mfa-ott)
     * </p>
     *
     * @return POST /login/mfa-ott (기본값)
     */
    public String getOttLoginProcessing() {
        AuthenticationProcessingOptions ottOpts = factorOptionsMap.get(AuthType.OTT);
        if (ottOpts instanceof OttOptions ottOptions) {
            String customUrl = ottOptions.getLoginProcessingUrl();
            if (StringUtils.hasText(customUrl)) {
                return customUrl;
            }
        }

        return properties.getUrls().getFactors().getOtt().getLoginProcessing();
    }

    /**
     * OTT 검증 실패 기본 URL
     * @return /mfa/challenge/ott?error=true (기본값)
     */
    public String getOttDefaultFailure() {
        return properties.getUrls().getFactors().getOtt().getDefaultFailure();
    }

    // ========================================
    // Passkey Factor URLs
    // ========================================

    /**
     * Passkey 검증 처리 URL (Filter가 처리)
     *
     * <p>
     * 우선순위:
     * 1. PasskeyOptions.loginProcessingUrl (DSL 커스텀 설정)
     * 2. AuthContextProperties 기본값 (/login/mfa-webauthn)
     * </p>
     *
     * @return POST /login/mfa-webauthn (기본값)
     */
    public String getPasskeyLoginProcessing() {
        AuthenticationProcessingOptions passkeyOpts = factorOptionsMap.get(AuthType.PASSKEY);
        if (passkeyOpts instanceof PasskeyOptions passkeyOptions) {
            String customUrl = passkeyOptions.getLoginProcessingUrl();
            if (StringUtils.hasText(customUrl)) {
                return customUrl;
            }
        }

        return properties.getUrls().getFactors().getPasskey().getLoginProcessing();
    }

    /**
     * Passkey 챌린지 UI 페이지
     *
     * <p>
     * 우선순위:
     * 1. MfaPageConfig.passkeyChallengePageUrl (DSL 커스텀 설정)
     * 2. AuthContextProperties 기본값 (/mfa/challenge/passkey)
     * </p>
     *
     * @return Passkey 챌린지 페이지 URL
     */
    public String getPasskeyChallengeUi() {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomPasskeyPage()) {
            return mfaPageConfig.getPasskeyChallengePageUrl();
        }
        return properties.getUrls().getFactors().getPasskey().getChallengeUi();
    }

    /**
     * Passkey 검증 실패 기본 URL
     * @return /mfa/challenge/passkey?error (기본값)
     */
    public String getPasskeyDefaultFailure() {
        return properties.getUrls().getFactors().getPasskey().getDefaultFailure();
    }

    /**
     * Passkey 등록 요청 URL
     * @return POST /mfa/passkey/register-request (기본값)
     */
    public String getPasskeyRegistrationRequest() {
        return properties.getUrls().getFactors().getPasskey().getRegistrationRequest();
    }

    /**
     * Passkey 등록 처리 URL
     * @return POST /mfa/passkey/register (기본값)
     */
    public String getPasskeyRegistrationProcessing() {
        return properties.getUrls().getFactors().getPasskey().getRegistrationProcessing();
    }

    /**
     * WebAuthn assertion options URL
     */
    public String getPasskeyAssertionOptions() {
        return properties.getUrls().getFactors().getPasskey().getAssertionOptions();
    }

    /**
     * WebAuthn registration options URL
     */
    public String getPasskeyRegistrationOptions() {
        return properties.getUrls().getFactors().getPasskey().getRegistrationOptions();
    }

    // ========================================
    // Recovery Code Factor URLs
    // ========================================

    /**
     * Recovery code 검증 처리 URL
     * @return POST /login/recovery/verify (기본값)
     */
    public String getRecoveryCodeLoginProcessing() {
        return properties.getUrls().getFactors().getRecoveryCodeLoginProcessing();
    }

    /**
     * Recovery code 챌린지 UI
     * @return GET /mfa/challenge/recovery (기본값)
     */
    public String getRecoveryCodeChallengeUi() {
        return properties.getUrls().getFactors().getRecoveryCodeChallengeUi();
    }

    // ========================================
    // Aggregate Methods (필터 및 SDK용)
    // ========================================

    /**
     * 모든 Factor 검증 처리 URL 반환 (MfaStepFilterWrapper용)
     * @return Factor 검증 URL 리스트
     */
    public List<String> getAllFactorProcessingUrls() {
        return List.of(
            getOttLoginProcessing(),
            getPasskeyLoginProcessing(),
            getRecoveryCodeLoginProcessing()
        );
    }

    /**
     * 모든 MFA 요청 URL 반환 (MfaUrlMatcher용)
     * @return MFA 요청 URL 리스트
     */
    public List<String> getAllMfaRequestUrls() {
        return List.of(
            getMfaInitiate(),
            getMfaSelectFactor(),
            getOttCodeGeneration(),
            getOttLoginProcessing(),
            getPasskeyLoginProcessing()
        );
    }

    /**
     * 모든 UI 페이지 URL 반환 (SDK 설정용)
     * @return URL Map (키: 식별자, 값: URL)
     */
    public Map<String, Object> getAllUiPageUrls() {
        Map<String, Object> urls = new LinkedHashMap<>();

        // Primary Auth
        urls.put("primary", Map.of(
            "formLoginPage", getPrimaryLoginPage(),
            "formLoginProcessing", getPrimaryFormLoginProcessing(),
            "restLoginProcessing", getPrimaryRestLoginProcessing(),
            "loginFailure", getPrimaryLoginFailure(),
            "loginSuccess", getPrimaryLoginSuccess()
        ));

        // MFA
        urls.put("mfa", Map.of(
            "initiate", getMfaInitiate(),
            "configure", getMfaConfigure(),
            "selectFactor", getMfaSelectFactor(),
            "success", getMfaSuccess(),
            "failure", getMfaFailure(),
            "cancel", getMfaCancel()
        ));

        // OTT Factor
        Map<String, String> ottUrls = new LinkedHashMap<>();
        ottUrls.put("requestCodeUi", getOttRequestCodeUi());
        ottUrls.put("challengeUi", getOttChallengeUi());
        ottUrls.put("loginProcessing", getOttLoginProcessing());
        ottUrls.put("codeSent", getOttCodeSent());
        ottUrls.put("codeGeneration", getOttCodeGeneration());
        ottUrls.put("defaultFailure", getOttDefaultFailure());
        ottUrls.put("singleOttRequestEmail", getSingleOttRequestEmail());
        ottUrls.put("singleOttCodeGeneration", getSingleOttCodeGeneration());
        ottUrls.put("singleOttChallenge", getSingleOttChallenge());
        ottUrls.put("singleOttSent", getSingleOttSent());
        urls.put("ott", ottUrls);

        // Passkey Factor
        Map<String, String> passkeyUrls = new LinkedHashMap<>();
        passkeyUrls.put("challengeUi", getPasskeyChallengeUi());
        passkeyUrls.put("loginProcessing", getPasskeyLoginProcessing());
        passkeyUrls.put("defaultFailure", getPasskeyDefaultFailure());
        passkeyUrls.put("registrationRequest", getPasskeyRegistrationRequest());
        passkeyUrls.put("registrationProcessing", getPasskeyRegistrationProcessing());
        urls.put("passkey", passkeyUrls);

        // Recovery Code Factor
        urls.put("recoveryCode", Map.of(
            "challengeUi", getRecoveryCodeChallengeUi(),
            "loginProcessing", getRecoveryCodeLoginProcessing()
        ));

        // WebAuthn (Passkey) - Spring Security 표준 엔드포인트
        urls.put("webauthn", Map.of(
            "assertionOptions", getPasskeyAssertionOptions(),
            "assertionVerify", getPasskeyLoginProcessing()  // MFA Passkey 검증: /login/mfa-webauthn
        ));

        // API (SDK 호환성)
        urls.put("api", Map.of(
            "selectFactor", getMfaSelectFactor(),
            "cancel", getMfaCancel(),
            "status", getMfaStatus(),
            "requestOttCode", getMfaRequestOttCode(),
            "context", getMfaContext(),
            "config", getMfaConfig()
        ));

        return urls;
    }

    // ========================================
    // Validation
    // ========================================

    /**
     * URL 설정 검증 - 애플리케이션 시작 시 자동 실행
     */
    @PostConstruct
    public void validateConfiguration() {
        List<String> errors = new ArrayList<>();
        Map<String, List<String>> urlToContexts = new LinkedHashMap<>();

        // 모든 URL을 컨텍스트와 함께 수집
        addUrlWithContext(urlToContexts, getPrimaryFormLoginProcessing(), "Primary.formLoginProcessing");
        addUrlWithContext(urlToContexts, getPrimaryRestLoginProcessing(), "Primary.restLoginProcessing");
        addUrlWithContext(urlToContexts, getPrimaryLoginPage(), "Primary.formLoginPage");
        addUrlWithContext(urlToContexts, getPrimaryLoginFailure(), "Primary.loginFailure");
        addUrlWithContext(urlToContexts, getPrimaryLoginSuccess(), "Primary.loginSuccess");
        addUrlWithContext(urlToContexts, getLogoutPage(), "Primary.logoutPage");

        addUrlWithContext(urlToContexts, getMfaInitiate(), "Mfa.initiate");
        addUrlWithContext(urlToContexts, getMfaConfigure(), "Mfa.configure");
        addUrlWithContext(urlToContexts, getMfaSelectFactor(), "Mfa.selectFactor");
        addUrlWithContext(urlToContexts, getMfaSuccess(), "Mfa.success");
        addUrlWithContext(urlToContexts, getMfaFailure(), "Mfa.failure");
        addUrlWithContext(urlToContexts, getMfaCancel(), "Mfa.cancel");

        addUrlWithContext(urlToContexts, getOttRequestCodeUi(), "Ott.requestCodeUi");
        addUrlWithContext(urlToContexts, getOttCodeGeneration(), "Ott.codeGeneration");
        addUrlWithContext(urlToContexts, getOttCodeSent(), "Ott.codeSent");
        addUrlWithContext(urlToContexts, getOttChallengeUi(), "Ott.challengeUi");
        addUrlWithContext(urlToContexts, getOttLoginProcessing(), "Ott.loginProcessing");
        addUrlWithContext(urlToContexts, getOttDefaultFailure(), "Ott.defaultFailure");
        addUrlWithContext(urlToContexts, getSingleOttRequestEmail(), "Ott.singleOttRequestEmail");
        addUrlWithContext(urlToContexts, getSingleOttCodeGeneration(), "Ott.singleOttCodeGeneration");
        addUrlWithContext(urlToContexts, getSingleOttChallenge(), "Ott.singleOttChallenge");
        addUrlWithContext(urlToContexts, getSingleOttSent(), "Ott.singleOttSent");

        addUrlWithContext(urlToContexts, getPasskeyLoginProcessing(), "Passkey.loginProcessing");
        addUrlWithContext(urlToContexts, getPasskeyChallengeUi(), "Passkey.challengeUi");
        addUrlWithContext(urlToContexts, getPasskeyDefaultFailure(), "Passkey.defaultFailure");
        addUrlWithContext(urlToContexts, getPasskeyRegistrationRequest(), "Passkey.registrationRequest");
        addUrlWithContext(urlToContexts, getPasskeyRegistrationProcessing(), "Passkey.registrationProcessing");
        addUrlWithContext(urlToContexts, getPasskeyRegistrationOptions(), "Passkey.registrationOptions");

        addUrlWithContext(urlToContexts, getRecoveryCodeLoginProcessing(), "RecoveryCode.loginProcessing");
        addUrlWithContext(urlToContexts, getRecoveryCodeChallengeUi(), "RecoveryCode.challengeUi");

        addUrlWithContext(urlToContexts, getMfaStatus(), "Mfa.status");
        addUrlWithContext(urlToContexts, getMfaContext(), "Mfa.context");
        addUrlWithContext(urlToContexts, getMfaRequestOttCode(), "Mfa.requestOttCode");
        addUrlWithContext(urlToContexts, getMfaConfig(), "Mfa.config");
        addUrlWithContext(urlToContexts, getPasskeyAssertionOptions(), "Passkey.assertionOptions");

        // 의도된 중복 URL 정의
        // - Form Login: GET(페이지 표시) + POST(로그인 처리)에 같은 URL 사용 (Spring Security 표준 패턴)
        // - 리다이렉트 목적지가 같은 경우
        Set<String> allowedDuplicates = Set.of(
            "/login",      // Single Auth Form Login (GET 페이지 + POST 처리)
            "/mfa/login",  // MFA Primary Auth Form Login (GET 페이지 + POST 처리)
            "/home",
            "/loginForm"
        );

        // 중복 검사
        List<String> problematicDuplicates = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry : urlToContexts.entrySet()) {
            String url = entry.getKey();
            List<String> contexts = entry.getValue();

            if (url == null || url.trim().isEmpty()) {
                errors.add("빈 URL이 발견되었습니다");
                continue;
            }

            // 중복이 있는 경우
            if (contexts.size() > 1) {
                // 의도된 중복인지 확인
                if (!allowedDuplicates.contains(url)) {
                    problematicDuplicates.add(url + " (사용처: " + String.join(", ", contexts) + ")");
                } else {
                    log.debug("의도된 중복 URL 허용: {} (사용처: {})", url, String.join(", ", contexts));
                }
            }
        }

        if (!problematicDuplicates.isEmpty()) {
            errors.add("의도하지 않은 중복 URL 발견: " + String.join("; ", problematicDuplicates));
        }

        // URL 형식 검증
        for (String url : urlToContexts.keySet()) {
            if (!url.startsWith("/")) {
                errors.add("URL은 '/'로 시작해야 합니다: " + url);
            }

            if (url.contains(" ")) {
                errors.add("URL에 공백이 포함되어 있습니다: " + url);
            }
        }

        // 오류 발생 시 예외
        if (!errors.isEmpty()) {
            String errorMessage = " URL 설정 검증 실패:\n" + String.join("\n", errors);
            log.error(errorMessage);
            throw new IllegalStateException(errorMessage);
        }

        log.info("URL 설정 검증 성공: {} 개의 고유 URL 설정됨 (의도된 중복 {} 개 허용)",
                urlToContexts.size(),
                urlToContexts.values().stream().filter(list -> list.size() > 1).count());
        log.debug("설정된 URL 목록:\n{}",
            urlToContexts.keySet().stream()
                .sorted()
                .map(url -> "  - " + url)
                .collect(Collectors.joining("\n"))
        );
    }

    /**
     * URL과 컨텍스트를 맵에 추가
     */
    private void addUrlWithContext(Map<String, List<String>> map, String url, String context) {
        if (url == null) return;
        map.computeIfAbsent(url, k -> new ArrayList<>()).add(context);
    }
}
