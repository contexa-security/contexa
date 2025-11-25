package io.contexa.autoconfigure.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.core.infrastructure.CoreInfrastructureAutoConfiguration;
import io.contexa.contexacore.autonomous.security.identification.UserIdentificationService;
import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import io.contexa.contexacore.infra.redis.RedisEventPublisher;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.bootstrap.*;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.FlowConfigurer;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.GlobalConfigurer;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.SecurityConfigurer;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.DefaultPlatformContext;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.FlowContextFactory;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.dsl.IdentityDslRegistry;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.core.validator.*;
import io.contexa.contexaidentity.security.filter.MfaFormAuthenticationFilter;
import io.contexa.contexaidentity.security.filter.MfaRestAuthenticationFilter;
import io.contexa.contexaidentity.security.filter.RestAuthenticationFilter;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.handler.MfaFactorProcessingSuccessHandler;
import io.contexa.contexaidentity.security.handler.PrimaryAuthenticationSuccessHandler;
import io.contexa.contexaidentity.security.handler.UnifiedAuthenticationFailureHandler;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.token.management.RefreshTokenAnomalyDetector;
import io.contexa.contexaidentity.security.token.management.TokenChainManager;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import io.contexa.contexaidentity.security.utils.writer.JsonAuthResponseWriter;
import jakarta.servlet.Filter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.ott.OneTimeTokenAuthenticationFilter;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationFilter;
import org.springframework.security.web.webauthn.management.JdbcPublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.JdbcUserCredentialRepository;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Identity Security Core AutoConfiguration
 *
 * <p>
 * Contexa Identity의 Security Core 관련 자동 구성을 제공합니다.
 * Security Platform, MFA Infrastructure, WebAuthn Persistence, Bootstrap, DSL, Validator 등을 명시적으로 등록합니다.
 * </p>
 *
 * <h3>등록되는 빈 (총 28개):</h3>
 * <ul>
 *   <li>Level 1: DSL (1개) - IdentityDslRegistry</li>
 *   <li>Level 2: Validator (8개) - DslValidatorService, DslValidator, 6개 Validator</li>
 *   <li>Level 3: Platform Context (3개) - PlatformContext, AdapterRegistry, PlatformContextInitializer</li>
 *   <li>Level 4: Security Configurers (3개) - FlowConfigurer, GlobalConfigurer, FactorFilterProvider</li>
 *   <li>Level 5: Security Platform (5개) - SecurityFilterChainRegistrar, FlowContextFactory, SecurityPlatform, PlatformBootstrap, WebSecurityConfigurationDependencyInjector</li>
 *   <li>Level 6: MFA Infrastructure (4개) - PrimaryAuthenticationSuccessHandler, UnifiedAuthenticationFailureHandler, MfaFactorProcessingSuccessHandler, AuthResponseWriter</li>
 *   <li>Level 7: WebAuthn Persistence (2개) - PublicKeyCredentialUserEntityRepository, UserCredentialRepository</li>
 *   <li>Level 8: Token Management (2개) - RefreshTokenAnomalyDetector, TokenChainManager</li>
 * </ul>
 *
 * <h3>활성화 조건:</h3>
 * <pre>
 * contexa:
 *   identity:
 *     security-core:
 *       enabled: true  # (기본값)
 * </pre>
 *
 * @since 0.1.0-ALPHA
 */
@Slf4j
@AutoConfiguration
@AutoConfigureAfter(CoreInfrastructureAutoConfiguration.class)
@EnableConfigurationProperties({AuthContextProperties.class})
@ConditionalOnProperty(
    prefix = "contexa.identity.security-core",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
public class IdentitySecurityCoreAutoConfiguration {

    public IdentitySecurityCoreAutoConfiguration() {
        log.info("IdentitySecurityCoreAutoConfiguration initialized - 28 beans registered");
    }

    // ========== Level 1: DSL (1개) ==========

    /**
     * 1-1. IdentityDslRegistry - Identity DSL 레지스트리
     */
    @Bean
    @ConditionalOnMissingBean
    public IdentityDslRegistry identityDslRegistry(ApplicationContext applicationContext) {
        return new IdentityDslRegistry(applicationContext);
    }

    // ========== Level 2: Validator (8개) ==========

    /**
     * 2-1. DslValidatorService - DSL 검증 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public DslValidatorService dslValidatorService(DslValidator dslValidator) {
        return new DslValidatorService(dslValidator);
    }

    /**
     * 2-2. DslValidator - DSL 검증기
     * <p>
     * Platform, Flow, Step 등 다양한 수준의 검증기를 조합하여 DSL 검증을 수행합니다.
     * </p>
     */
    @Bean
    @ConditionalOnMissingBean
    public DslValidator dslValidator(
            ObjectProvider<List<Validator<PlatformConfig>>> platformConfigValidatorsProvider,
            ObjectProvider<List<Validator<List<AuthenticationFlowConfig>>>> flowListValidatorsProvider,
            ObjectProvider<List<Validator<AuthenticationFlowConfig>>> singleFlowValidatorsProvider,
            ObjectProvider<List<Validator<AuthenticationStepConfig>>> stepValidatorsProvider) {

        List<Validator<PlatformConfig>> platformValidators = platformConfigValidatorsProvider.getIfAvailable(Collections::emptyList);
        List<Validator<List<AuthenticationFlowConfig>>> flowListValidators = flowListValidatorsProvider.getIfAvailable(Collections::emptyList);
        List<Validator<AuthenticationFlowConfig>> singleFlowValidators = singleFlowValidatorsProvider.getIfAvailable(Collections::emptyList);
        List<Validator<AuthenticationStepConfig>> stepValidators = stepValidatorsProvider.getIfAvailable(Collections::emptyList);

        log.info("Creating DslValidator with platform={}, flowList={}, singleFlow={}, step={} validators",
                platformValidators.size(), flowListValidators.size(), singleFlowValidators.size(), stepValidators.size());

        return new DslValidator(
                platformValidators,
                flowListValidators,
                singleFlowValidators,
                stepValidators
        );
    }

    /**
     * 2-3. LoginProcessingUrlUniquenessValidator - 로그인 URL 중복 검증
     */
    @Bean
    @ConditionalOnMissingBean
    public LoginProcessingUrlUniquenessValidator loginProcessingUrlUniquenessValidator() {
        return new LoginProcessingUrlUniquenessValidator();
    }

    /**
     * 2-4. MfaFlowStructureValidator - MFA Flow 구조 검증
     */
    @Bean
    @ConditionalOnMissingBean
    public MfaFlowStructureValidator mfaFlowStructureValidator() {
        return new MfaFlowStructureValidator();
    }

    /**
     * 2-5. RequiredPlatformOptionsValidator - 필수 플랫폼 옵션 검증
     */
    @Bean
    @ConditionalOnMissingBean
    public RequiredPlatformOptionsValidator requiredPlatformOptionsValidator() {
        return new RequiredPlatformOptionsValidator();
    }

    /**
     * 2-6. FeatureAvailabilityValidator - 기능 가용성 검증
     */
    @Bean
    @ConditionalOnMissingBean
    public FeatureAvailabilityValidator featureAvailabilityValidator(AdapterRegistry adapterRegistry) {
        return new FeatureAvailabilityValidator(adapterRegistry);
    }

    /**
     * 2-7. CustomBeanDependencyValidator - 커스텀 빈 의존성 검증
     */
    @Bean
    @ConditionalOnMissingBean
    public CustomBeanDependencyValidator customBeanDependencyValidator(ApplicationContext applicationContext) {
        return new CustomBeanDependencyValidator(applicationContext);
    }

    /**
     * 2-8. DuplicateFlowTypeNameValidator - Flow 타입 이름 중복 검증
     */
    @Bean
    @ConditionalOnMissingBean
    public DuplicateFlowTypeNameValidator duplicateFlowTypeNameValidator() {
        return new DuplicateFlowTypeNameValidator();
    }

    // ========== Level 3: Platform Context (3개) ==========

    /**
     * 3-1. PlatformContext - 플랫폼 컨텍스트
     * <p>
     * ApplicationContext와 HttpSecurity를 캡슐화하여 플랫폼 전역에서 사용합니다.
     * </p>
     */
    @Bean
    @ConditionalOnMissingBean
    public PlatformContext platformContext(ApplicationContext ctx,
                                           ObjectProvider<HttpSecurity> provider) {
        log.info("Creating PlatformContext");
        return new DefaultPlatformContext(ctx, provider);
    }

    /**
     * 3-2. AdapterRegistry - 어댑터 레지스트리
     * <p>
     * 다양한 인증 방식의 어댑터들을 등록하고 관리합니다.
     * </p>
     */
    @Bean
    @ConditionalOnMissingBean
    public AdapterRegistry adapterRegistry(ApplicationContext applicationContext) {
        log.info("Creating AdapterRegistry");
        return new AdapterRegistry(applicationContext);
    }

    /**
     * 3-3. PlatformContextInitializer - 플랫폼 컨텍스트 초기화기
     * <p>
     * PlatformContext의 공유 객체들을 초기화합니다.
     * </p>
     */
    @Bean
    @ConditionalOnMissingBean
    public PlatformContextInitializer platformContextInitializer(PlatformContext platformContext,
                                                                 AuthContextProperties authContextProperties,
                                                                 ObjectMapper objectMapper) {
        log.info("Creating PlatformContextInitializer");
        return new PlatformContextInitializer(platformContext, authContextProperties, objectMapper);
    }

    // ========== Level 4: Security Configurers (3개) ==========

    /**
     * 4-1. FlowConfigurer - Flow 설정기
     */
    @Bean
    @ConditionalOnMissingBean
    public SecurityConfigurer flowConfigurer() {
        return new FlowConfigurer();
    }

    /**
     * 4-2. GlobalConfigurer - 전역 설정기
     */
    @Bean
    @ConditionalOnMissingBean
    public SecurityConfigurer globalConfigurer() {
        return new GlobalConfigurer();
    }

    /**
     * 4-3. ConfiguredFactorFilterProvider - Factor Filter 제공자
     */
    @Bean
    @ConditionalOnMissingBean
    public ConfiguredFactorFilterProvider factorFilterProvider() {
        return new ConfiguredFactorFilterProvider();
    }

    // ========== Level 5: Security Platform (5개) ==========

    /**
     * 5-1. SecurityFilterChainRegistrar - Security Filter Chain 등록기
     * <p>
     * 인증 방식별 Filter 클래스를 매핑하고 SecurityFilterChain을 등록합니다.
     * </p>
     */
    @Bean
    @ConditionalOnMissingBean
    public SecurityFilterChainRegistrar securityFilterChainRegistrar(
            ConfiguredFactorFilterProvider factorFilterProvider,
            AdapterRegistry adapterRegistry) {
        log.info("Creating SecurityFilterChainRegistrar with 8 step filter mappings");
        Map<String, Class<? extends Filter>> stepFilterClasses = Map.ofEntries(
                Map.entry("form", UsernamePasswordAuthenticationFilter.class),
                Map.entry("rest", RestAuthenticationFilter.class),
                Map.entry("mfa_rest", MfaRestAuthenticationFilter.class),
                Map.entry("mfa_form", MfaFormAuthenticationFilter.class),
                Map.entry("ott", OneTimeTokenAuthenticationFilter.class),
                Map.entry("mfa_ott", OneTimeTokenAuthenticationFilter.class),
                Map.entry("passkey", WebAuthnAuthenticationFilter.class),
                Map.entry("mfa_passkey", WebAuthnAuthenticationFilter.class)
        );
        return new SecurityFilterChainRegistrar(factorFilterProvider,
                stepFilterClasses, // stepFilterClasses는 DSL에서 동적으로 결정되므로 빈 Map 사용
                adapterRegistry);
    }

    /**
     * 5-2. FlowContextFactory - Flow Context 팩토리
     */
    @Bean
    @ConditionalOnMissingBean
    public FlowContextFactory flowContextFactory(AdapterRegistry adapterRegistry, ApplicationContext applicationContext) {
        log.info("Creating FlowContextFactory");
        return new FlowContextFactory(adapterRegistry, applicationContext);
    }

    /**
     * 5-3. SecurityPlatform - Security 플랫폼
     * <p>
     * Security Platform의 핵심 컴포넌트로, 전체 보안 설정을 초기화합니다.
     * </p>
     */
    @Bean
    @ConditionalOnMissingBean
    public SecurityPlatform securityPlatform(PlatformContext context,
                                             List<SecurityConfigurer> allRegisteredConfigurers,
                                             AdapterRegistry adapterRegistry,
                                             PlatformContextInitializer platformContextInitializer,
                                             SecurityFilterChainRegistrar securityFilterChainRegistrar,
                                             FlowContextFactory flowContextFactory,
                                             PlatformConfig platformConfig,
                                             ApplicationContext applicationContext) {
        log.info("Creating SecurityPlatform with {} configurers", allRegisteredConfigurers.size());
        platformContextInitializer.initializeSharedObjects();

        DefaultSecurityConfigurerProvider configurerProvider =
                new DefaultSecurityConfigurerProvider(allRegisteredConfigurers, adapterRegistry, applicationContext);

        return new SecurityPlatformInitializer(
                context,
                platformConfig,
                securityFilterChainRegistrar,
                flowContextFactory,
                new SecurityConfigurerOrchestrator(configurerProvider)
        );
    }

    /**
     * 5-4. PlatformBootstrap - 플랫폼 부트스트랩
     * <p>
     * Security Platform을 부트스트랩하고 초기화를 완료합니다.
     * </p>
     */
    @Bean
    @ConditionalOnMissingBean
    public PlatformBootstrap platformBootstrap(SecurityPlatform securityPlatform,
                                               PlatformConfig platformConfig,
                                               AdapterRegistry registry,
                                               DslValidatorService dslValidatorService) {
        log.info("Creating PlatformBootstrap");
        return new PlatformBootstrap(securityPlatform, platformConfig, registry, dslValidatorService);
    }

    /**
     * 5-5. WebSecurityConfigurationDependencyInjector - WebSecurityConfiguration 의존성 주입기
     */
    @Bean
    @ConditionalOnMissingBean
    public WebSecurityConfigurationDependencyInjector webSecurityConfigurationDependencyInjector() {
        return new WebSecurityConfigurationDependencyInjector();
    }

    // ========== Level 6: MFA Infrastructure (4개) ==========

    /**
     * 6-1. PrimaryAuthenticationSuccessHandler - 주요 인증 성공 핸들러
     * <p>
     * MFA 정책에 따라 추가 인증 여부를 결정하고 처리합니다.
     * </p>
     */
    @Bean
    @ConditionalOnMissingBean
    public PrimaryAuthenticationSuccessHandler primaryAuthenticationSuccessHandler(
            AuthResponseWriter authResponseWriter,
            MfaPolicyProvider mfaPolicyProvider,
            ApplicationContext applicationContext,
            MfaStateMachineIntegrator mfaStateMachineIntegrator,
            MfaSessionRepository mfaSessionRepository,
            AuthUrlProvider authUrlProvider,
            TokenService tokenService,
            AuthContextProperties authContextProperties) {
        log.info("Creating PrimaryAuthenticationSuccessHandler");
        return new PrimaryAuthenticationSuccessHandler(mfaPolicyProvider, tokenService, authResponseWriter,
                authContextProperties, applicationContext, mfaStateMachineIntegrator, mfaSessionRepository, authUrlProvider);
    }

    /**
     * 6-2. UnifiedAuthenticationFailureHandler - 통합 인증 실패 핸들러
     */
    @Bean
    @ConditionalOnMissingBean
    public UnifiedAuthenticationFailureHandler unifiedAuthenticationFailureHandler(
            MfaStateMachineIntegrator mfaStateMachineIntegrator,
            MfaPolicyProvider mfaPolicyProvider,
            AuthResponseWriter authResponseWriter,
            MfaSessionRepository mfaSessionRepository,
            UserIdentificationService userIdentificationService,
            AuthUrlProvider authUrlProvider) {
        log.info("Creating UnifiedAuthenticationFailureHandler");
        return new UnifiedAuthenticationFailureHandler(authResponseWriter, mfaStateMachineIntegrator, mfaPolicyProvider,
                mfaSessionRepository, userIdentificationService, authUrlProvider);
    }

    /**
     * 6-3. MfaFactorProcessingSuccessHandler - MFA Factor 처리 성공 핸들러
     */
    @Bean
    @ConditionalOnMissingBean
    public MfaFactorProcessingSuccessHandler mfaFactorProcessingSuccessHandler(
            MfaStateMachineIntegrator mfaStateMachineIntegrator,
            AuthResponseWriter authResponseWriter,
            MfaSessionRepository mfaSessionRepository,
            AuthUrlProvider authUrlProvider,
            AuthContextProperties authContextProperties,
            TokenService tokenService) {
        log.info("Creating MfaFactorProcessingSuccessHandler");
        return new MfaFactorProcessingSuccessHandler(mfaStateMachineIntegrator, authResponseWriter,
                authContextProperties, mfaSessionRepository, tokenService, authUrlProvider);
    }

    /**
     * 6-4. AuthResponseWriter - 인증 응답 작성기
     * <p>
     * JSON 형식으로 인증 응답을 작성합니다.
     * </p>
     */
    @Bean
    @ConditionalOnMissingBean
    public AuthResponseWriter authResponseWriter(ObjectMapper objectMapper) {
        log.info("Creating JsonAuthResponseWriter");
        return new JsonAuthResponseWriter(objectMapper);
    }

    // ========== Level 7: WebAuthn Persistence (2개) ==========

    /**
     * 7-1. PublicKeyCredentialUserEntityRepository - WebAuthn User Entity Repository
     * <p>
     * user_entities 테이블에 WebAuthn UserEntity를 저장/조회합니다.
     * </p>
     */
    @Bean
    @ConditionalOnMissingBean
    public PublicKeyCredentialUserEntityRepository publicKeyCredentialUserEntityRepository(
            JdbcOperations jdbcOperations) {
        log.info("Creating PublicKeyCredentialUserEntityRepository (JDBC-based)");
        return new JdbcPublicKeyCredentialUserEntityRepository(jdbcOperations);
    }

    /**
     * 7-2. UserCredentialRepository - WebAuthn Credential Repository
     * <p>
     * user_credentials 테이블에 등록된 Passkey를 저장/조회합니다.
     * </p>
     */
    @Bean
    @ConditionalOnMissingBean
    public UserCredentialRepository userCredentialRepository(
            JdbcOperations jdbcOperations) {
        log.info("Creating UserCredentialRepository (JDBC-based)");
        return new JdbcUserCredentialRepository(jdbcOperations);
    }

    // ========== Level 8: Token Management (2개) ==========

    /**
     * 8-1. RefreshTokenAnomalyDetector - 리프레시 토큰 비정상 패턴 감지
     */
    @Bean
    @ConditionalOnMissingBean
    public RefreshTokenAnomalyDetector refreshTokenAnomalyDetector(
            StringRedisTemplate redisTemplate,
            RedisEventPublisher redisEventPublisher) {
        log.info("Creating RefreshTokenAnomalyDetector");
        return new RefreshTokenAnomalyDetector(redisTemplate, redisEventPublisher);
    }

    /**
     * 8-2. TokenChainManager - 토큰 체인 관리
     */
    @Bean
    @ConditionalOnMissingBean
    public TokenChainManager tokenChainManager(
            StringRedisTemplate redisTemplate,
            RedisDistributedLockService lockService) {
        log.info("Creating TokenChainManager");
        return new TokenChainManager(redisTemplate, lockService);
    }
}
