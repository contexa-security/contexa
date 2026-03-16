package io.contexa.autoconfigure.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.core.infra.CoreInfrastructureAutoConfiguration;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.bootstrap.*;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.*;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.DefaultPlatformContext;
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
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import io.contexa.contexaidentity.security.utils.JsonAuthResponseWriter;
import io.contexa.contexaidentity.security.zerotrust.ChallengeMfaInitializer;
import io.contexa.contexaidentity.security.zerotrust.ZeroTrustAccessControlFilter;
import io.contexa.contexaidentity.security.zerotrust.ZeroTrustChallengeFilter;
import jakarta.servlet.Filter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
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
import java.util.UUID;


@Slf4j
@AutoConfiguration
@AutoConfigureAfter(CoreInfrastructureAutoConfiguration.class)
@EnableConfigurationProperties({AuthContextProperties.class })
@ConditionalOnProperty(prefix = "contexa.identity.security-core", name = "enabled", havingValue = "true", matchIfMissing = true)
@ConditionalOnBean(PlatformConfig.class)
public class IdentitySecurityCoreAutoConfiguration {

    public IdentitySecurityCoreAutoConfiguration() {
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.securityMatcher("/" + UUID.randomUUID())
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
        return httpSecurity.build();
    }

    @Bean
    @ConditionalOnMissingBean
    public IdentityDslRegistry identityDslRegistry(ApplicationContext applicationContext) {
        return new IdentityDslRegistry(applicationContext);
    }

    @Bean
    @ConditionalOnMissingBean
    public DslValidator dslValidator(
            ObjectProvider<List<Validator<PlatformConfig>>> platformConfigValidatorsProvider,
            ObjectProvider<List<Validator<List<AuthenticationFlowConfig>>>> flowListValidatorsProvider,
            ObjectProvider<List<Validator<AuthenticationFlowConfig>>> singleFlowValidatorsProvider,
            ObjectProvider<List<Validator<AuthenticationStepConfig>>> stepValidatorsProvider) {

        List<Validator<PlatformConfig>> platformValidators = platformConfigValidatorsProvider
                .getIfAvailable(Collections::emptyList);
        List<Validator<List<AuthenticationFlowConfig>>> flowListValidators = flowListValidatorsProvider
                .getIfAvailable(Collections::emptyList);
        List<Validator<AuthenticationFlowConfig>> singleFlowValidators = singleFlowValidatorsProvider
                .getIfAvailable(Collections::emptyList);
        List<Validator<AuthenticationStepConfig>> stepValidators = stepValidatorsProvider
                .getIfAvailable(Collections::emptyList);

        return new DslValidator(
                platformValidators,
                flowListValidators,
                singleFlowValidators,
                stepValidators);
    }

    @Bean
    @ConditionalOnMissingBean
    public LoginProcessingUrlUniquenessValidator loginProcessingUrlUniquenessValidator() {
        return new LoginProcessingUrlUniquenessValidator();
    }

    @Bean
    @ConditionalOnMissingBean
    public MfaFlowStructureValidator mfaFlowStructureValidator() {
        return new MfaFlowStructureValidator();
    }

    @Bean
    @ConditionalOnMissingBean
    public PasskeyOptionsValidator passkeyOptionsValidator() {
        return new PasskeyOptionsValidator();
    }

    @Bean
    @ConditionalOnMissingBean
    public FeatureAvailabilityValidator featureAvailabilityValidator(AdapterRegistry adapterRegistry) {
        return new FeatureAvailabilityValidator(adapterRegistry);
    }

    @Bean
    @ConditionalOnMissingBean
    public DuplicateFlowTypeNameValidator duplicateFlowTypeNameValidator() {
        return new DuplicateFlowTypeNameValidator();
    }

    @Bean
    @ConditionalOnMissingBean
    public PlatformContext platformContext(ApplicationContext ctx, ObjectProvider<HttpSecurity> provider) {
        return new DefaultPlatformContext(ctx, provider);
    }

    @Bean
    @ConditionalOnMissingBean
    public AdapterRegistry adapterRegistry(ApplicationContext applicationContext) {
        return new AdapterRegistry(applicationContext);
    }

    @Bean
    @ConditionalOnMissingBean
    public PlatformContextInitializer platformContextInitializer(PlatformContext platformContext,
            AuthContextProperties authContextProperties,
            ObjectMapper objectMapper) {
        return new PlatformContextInitializer(platformContext, authContextProperties, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean(FlowConfigurer.class)
    public SecurityConfigurer flowConfigurer() {
        return new FlowConfigurer();
    }

    @Bean
    @ConditionalOnMissingBean(GlobalConfigurer.class)
    public SecurityConfigurer globalConfigurer() {
        return new GlobalConfigurer();
    }

    @Bean
    @ConditionalOnMissingBean
    public ConfiguredFactorFilterProvider factorFilterProvider() {
        return new ConfiguredFactorFilterProvider();
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityFilterChainRegistrar securityFilterChainRegistrar(
            ConfiguredFactorFilterProvider factorFilterProvider,
            AdapterRegistry adapterRegistry) {
        Map<String, Class<? extends Filter>> stepFilterClasses = Map.ofEntries(
                Map.entry("form", UsernamePasswordAuthenticationFilter.class),
                Map.entry("rest", RestAuthenticationFilter.class),
                Map.entry("mfa_rest", MfaRestAuthenticationFilter.class),
                Map.entry("mfa_form", MfaFormAuthenticationFilter.class),
                Map.entry("ott", OneTimeTokenAuthenticationFilter.class),
                Map.entry("mfa_ott", OneTimeTokenAuthenticationFilter.class),
                Map.entry("passkey", WebAuthnAuthenticationFilter.class),
                Map.entry("mfa_passkey", WebAuthnAuthenticationFilter.class));
        return new SecurityFilterChainRegistrar(factorFilterProvider, stepFilterClasses);
    }

    @Bean
    @ConditionalOnMissingBean
    public FlowContextFactory flowContextFactory(ApplicationContext applicationContext) {
        return new FlowContextFactory(applicationContext);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityPlatform securityPlatform(PlatformContext context,
            List<SecurityConfigurer> allRegisteredConfigurers,
            AdapterRegistry adapterRegistry,
            PlatformContextInitializer platformContextInitializer,
            SecurityFilterChainRegistrar securityFilterChainRegistrar,
            FlowContextFactory flowContextFactory,
            PlatformConfig platformConfig) {
        platformContextInitializer.initializeSharedObjects();

        DefaultSecurityConfigurerProvider configurerProvider = new DefaultSecurityConfigurerProvider(
                allRegisteredConfigurers, adapterRegistry);

        return new SecurityPlatformInitializer(
                context,
                platformConfig,
                securityFilterChainRegistrar,
                flowContextFactory,
                new SecurityConfigurerOrchestrator(configurerProvider));
    }

    @Bean
    @ConditionalOnMissingBean
    public PlatformBootstrap platformBootstrap(SecurityPlatform securityPlatform,
            PlatformConfig platformConfig,
            AdapterRegistry registry,
            DslValidator dslValidator) {
        return new PlatformBootstrap(securityPlatform, platformConfig, registry, dslValidator);
    }

    @Bean
    @ConditionalOnMissingBean
    public WebSecurityConfigurationDependencyInjector webSecurityConfigurationDependencyInjector() {
        return new WebSecurityConfigurationDependencyInjector();
    }

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
            AuthContextProperties authContextProperties,
            ZeroTrustEventPublisher zeroTrustEventPublisher,
            ZeroTrustActionRepository actionRedisRepository,
            SecurityLearningService securityLearningService,
            IBlockedUserRecorder blockedUserRecorder,
            BlockMfaStateStore blockMfaStateStore,
            CentralAuditFacade centralAuditFacade) {
        return new PrimaryAuthenticationSuccessHandler(mfaPolicyProvider, tokenService, authResponseWriter,
                authContextProperties, applicationContext, mfaStateMachineIntegrator, mfaSessionRepository,
                authUrlProvider, zeroTrustEventPublisher, actionRedisRepository, securityLearningService,
                blockedUserRecorder, blockMfaStateStore, centralAuditFacade);
    }

    @Bean
    @ConditionalOnMissingBean
    public UnifiedAuthenticationFailureHandler unifiedAuthenticationFailureHandler(
            MfaStateMachineIntegrator mfaStateMachineIntegrator,
            AuthResponseWriter authResponseWriter,
            MfaSessionRepository mfaSessionRepository,
            ZeroTrustEventPublisher zeroTrustEventPublisher,
            ZeroTrustActionRepository actionRedisRepository,
            AuthContextProperties authContextProperties,
            IBlockedUserRecorder blockedUserRecorder,
            @Autowired(required = false) CentralAuditFacade centralAuditFacade) {
        return new UnifiedAuthenticationFailureHandler(authResponseWriter, mfaStateMachineIntegrator,
                mfaSessionRepository, zeroTrustEventPublisher, actionRedisRepository,
                authContextProperties.getMfa(), blockedUserRecorder, centralAuditFacade);
    }

    @Bean
    @ConditionalOnMissingBean
    public MfaFactorProcessingSuccessHandler mfaFactorProcessingSuccessHandler(
            MfaStateMachineIntegrator mfaStateMachineIntegrator,
            AuthResponseWriter authResponseWriter,
            MfaSessionRepository mfaSessionRepository,
            AuthUrlProvider authUrlProvider,
            AuthContextProperties authContextProperties,
            TokenService tokenService,
            ZeroTrustEventPublisher zeroTrustEventPublisher,
            ZeroTrustActionRepository actionRedisRepository,
            SecurityLearningService securityLearningService,
            ApplicationContext applicationContext,
            IBlockedUserRecorder blockedUserRecorder,
            BlockMfaStateStore blockMfaStateStore,
            CentralAuditFacade centralAuditFacade) {
        return new MfaFactorProcessingSuccessHandler(mfaStateMachineIntegrator, authResponseWriter,
                authContextProperties, mfaSessionRepository, tokenService, authUrlProvider,
                zeroTrustEventPublisher, actionRedisRepository, securityLearningService, applicationContext,
                blockedUserRecorder, blockMfaStateStore, centralAuditFacade);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthResponseWriter authResponseWriter(ObjectMapper objectMapper) {
        return new JsonAuthResponseWriter(objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public ChallengeMfaInitializer challengeMfaInitializer(
            MfaSessionRepository sessionRepository,
            MfaStateMachineIntegrator stateMachineIntegrator,
            MfaPolicyProvider mfaPolicyProvider,
            PlatformConfig platformConfig) {
        return new ChallengeMfaInitializer(
                sessionRepository, stateMachineIntegrator, mfaPolicyProvider, platformConfig);
    }

    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustChallengeFilter zeroTrustChallengeFilter(
            ChallengeMfaInitializer challengeMfaInitializer,
            AuthResponseWriter responseWriter,
            AuthUrlProvider authUrlProvider,
            MfaSessionRepository sessionRepository,
            MfaStateMachineIntegrator stateMachineIntegrator,
            DistributedLockService lockService) {

        return new ZeroTrustChallengeFilter(
                challengeMfaInitializer, responseWriter, authUrlProvider,
                sessionRepository, stateMachineIntegrator, lockService);
    }

    @Bean
    @ConditionalOnBean(ZeroTrustChallengeFilter.class)
    public FilterRegistrationBean zeroTrustChallengeFilterRegistrationBean(ZeroTrustChallengeFilter zeroTrustChallengeFilter){
        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
        filterRegistrationBean.setFilter(zeroTrustChallengeFilter);
        filterRegistrationBean.setEnabled(false);
        return filterRegistrationBean;
    }

    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustChallengeConfigurer zeroTrustChallengeConfigurer(
            ZeroTrustChallengeFilter zeroTrustChallengeFilter) {
        return new ZeroTrustChallengeConfigurer(zeroTrustChallengeFilter);
    }

    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustAccessControlFilter zeroTrustAccessControlFilter(
            ZeroTrustActionRepository actionRedisRepository,
            AuthResponseWriter responseWriter,
            IBlockedUserRecorder blockedUserRecorder,
            ChallengeMfaInitializer challengeMfaInitializer,
            AuthUrlProvider authUrlProvider,
            BlockingSignalBroadcaster blockingDecisionRegistry,
            SecurityZeroTrustProperties securityZeroTrustProperties) {
        return new ZeroTrustAccessControlFilter(actionRedisRepository, responseWriter,
                blockedUserRecorder, challengeMfaInitializer, authUrlProvider, blockingDecisionRegistry,
                securityZeroTrustProperties.getMaxBlockMfaAttempts());
    }

    @Bean
    @ConditionalOnBean(ZeroTrustAccessControlFilter.class)
    public FilterRegistrationBean<ZeroTrustAccessControlFilter> zeroTrustAccessControlFilterRegistrationBean(
            ZeroTrustAccessControlFilter zeroTrustAccessControlFilter) {
        FilterRegistrationBean<ZeroTrustAccessControlFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(zeroTrustAccessControlFilter);
        registrationBean.setEnabled(false);
        return registrationBean;
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(ZeroTrustAccessControlFilter.class)
    public ZeroTrustAccessControlConfigurer zeroTrustAccessControlConfigurer(
            ZeroTrustAccessControlFilter zeroTrustAccessControlFilter) {
        return new ZeroTrustAccessControlConfigurer(zeroTrustAccessControlFilter);
    }

    @Bean
    @ConditionalOnMissingBean
    public PublicKeyCredentialUserEntityRepository publicKeyCredentialUserEntityRepository(
            JdbcOperations jdbcOperations) {
        return new JdbcPublicKeyCredentialUserEntityRepository(jdbcOperations);
    }

    @Bean
    @ConditionalOnMissingBean
    public UserCredentialRepository userCredentialRepository(
            JdbcOperations jdbcOperations) {
        return new JdbcUserCredentialRepository(jdbcOperations);
    }

}
