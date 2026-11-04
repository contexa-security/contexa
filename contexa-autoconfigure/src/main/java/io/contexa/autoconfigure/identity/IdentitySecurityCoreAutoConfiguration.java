/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.autoconfigure.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.core.infra.CoreInfrastructureAutoConfiguration;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.autoconfigure.ai.HostOwnedEnforcementOrder;
import io.contexa.contexaidentity.security.zerotrust.HostOwnedStepUp;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.UnanalysedRequestRecorder;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineService;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import io.contexa.contexaidentity.security.core.session.HttpSessionCleanupListener;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
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
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.filter.MfaFormAuthenticationFilter;
import io.contexa.contexaidentity.security.filter.MfaPendingAccessControlFilter;
import io.contexa.contexaidentity.security.filter.MfaRestAuthenticationFilter;
import io.contexa.contexaidentity.security.filter.RestAuthenticationFilter;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import io.contexa.contexaidentity.security.utils.JsonAuthResponseWriter;
import io.contexa.contexaidentity.security.zerotrust.ChallengeMfaInitializer;
import io.contexa.contexaidentity.security.zerotrust.ZeroTrustAccessControlFilter;
import io.contexa.contexaidentity.security.zerotrust.ZeroTrustChallengeFilter;
import io.contexa.contexacore.autonomous.agent.AgentContainmentService;
import io.contexa.contexaidentity.security.zerotrust.AgentConfirmationGate;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationService;
import io.contexa.contexacore.autonomous.agent.AgentCallGuard;
import io.contexa.contexacore.autonomous.agent.AgentScopeService;
import jakarta.servlet.Filter;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Bean;
import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.ott.OneTimeTokenAuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationFilter;



@Slf4j
@AutoConfiguration
@AutoConfigureAfter(CoreInfrastructureAutoConfiguration.class)
@EnableConfigurationProperties({AuthContextProperties.class })
@ConditionalOnProperty(prefix = "contexa.identity.security-core", name = "enabled", havingValue = "true", matchIfMissing = true)
@ConditionalOnBean(PlatformConfig.class)
@Import(IdentitySecurityCoreContexaOwnedConfiguration.class)
public class IdentitySecurityCoreAutoConfiguration {

    public IdentitySecurityCoreAutoConfiguration() {
    }

    @Bean(name = "contexaIdentityDslRegistry")
    @ConditionalOnMissingBean
    public IdentityDslRegistry identityDslRegistry(ApplicationContext applicationContext) {
        return new IdentityDslRegistry(applicationContext);
    }

    @Bean(name = "contexaDslValidator")
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

    @Bean(name = "contexaLoginProcessingUrlUniquenessValidator")
    @ConditionalOnMissingBean
    public LoginProcessingUrlUniquenessValidator loginProcessingUrlUniquenessValidator() {
        return new LoginProcessingUrlUniquenessValidator();
    }

    @Bean(name = "contexaMfaFlowStructureValidator")
    @ConditionalOnMissingBean
    public MfaFlowStructureValidator mfaFlowStructureValidator() {
        return new MfaFlowStructureValidator();
    }

    @Bean(name = "contexaPasskeyOptionsValidator")
    @ConditionalOnMissingBean
    public PasskeyOptionsValidator passkeyOptionsValidator() {
        return new PasskeyOptionsValidator();
    }

    @Bean(name = "contexaMfaPasskeyRegistrationPathValidator")
    @ConditionalOnMissingBean
    public MfaPasskeyRegistrationPathValidator mfaPasskeyRegistrationPathValidator() {
        return new MfaPasskeyRegistrationPathValidator();
    }

    @Bean(name = "contexaFeatureAvailabilityValidator")
    @ConditionalOnMissingBean
    public AdapterAvailabilityValidator featureAvailabilityValidator(AdapterRegistry contexaAdapterRegistry) {
        return new AdapterAvailabilityValidator(contexaAdapterRegistry);
    }

    @Bean(name = "contexaDuplicateFlowTypeNameValidator")
    @ConditionalOnMissingBean
    public DuplicateFlowTypeNameValidator duplicateFlowTypeNameValidator() {
        return new DuplicateFlowTypeNameValidator();
    }

    @Bean(name = "contexaPlatformContext")
    @ConditionalOnMissingBean
    public PlatformContext platformContext(ApplicationContext ctx, ObjectProvider<HttpSecurity> provider) {
        return new DefaultPlatformContext(ctx, provider);
    }

    @Bean(name = "contexaAdapterRegistry")
    @ConditionalOnMissingBean
    public AdapterRegistry adapterRegistry(ApplicationContext applicationContext) {
        return new AdapterRegistry(applicationContext);
    }

    @Bean(name = "contexaPlatformContextInitializer")
    @ConditionalOnMissingBean
    public PlatformContextInitializer platformContextInitializer(PlatformContext contexaPlatformContext,
            AuthContextProperties authContextProperties,
            @Qualifier("contexaObjectMapper") ObjectMapper objectMapper) {
        return new PlatformContextInitializer(contexaPlatformContext, authContextProperties, objectMapper);
    }

    @Bean(name = "contexaFlowConfigurer")
    @ConditionalOnMissingBean(FlowConfigurer.class)
    public SecurityConfigurer flowConfigurer() {
        return new FlowConfigurer();
    }

    @Bean(name = "contexaGlobalConfigurer")
    @ConditionalOnMissingBean(GlobalConfigurer.class)
    public SecurityConfigurer globalConfigurer() {
        return new GlobalConfigurer();
    }

    @Bean(name = "contexaFactorFilterProvider")
    @ConditionalOnMissingBean
    public ConfiguredFactorFilterProvider factorFilterProvider() {
        return new ConfiguredFactorFilterProvider();
    }

    @Bean(name = "contexaSecurityFilterChainRegistrar")
    @ConditionalOnMissingBean
    public SecurityFilterChainRegistrar securityFilterChainRegistrar(
            ConfiguredFactorFilterProvider contexaFactorFilterProvider,
            AdapterRegistry contexaAdapterRegistry) {
        Map<String, Class<? extends Filter>> stepFilterClasses = Map.ofEntries(
                Map.entry("form", UsernamePasswordAuthenticationFilter.class),
                Map.entry("rest", RestAuthenticationFilter.class),
                Map.entry("mfa_rest", MfaRestAuthenticationFilter.class),
                Map.entry("mfa_form", MfaFormAuthenticationFilter.class),
                Map.entry("ott", OneTimeTokenAuthenticationFilter.class),
                Map.entry("mfa_ott", OneTimeTokenAuthenticationFilter.class),
                Map.entry("passkey", WebAuthnAuthenticationFilter.class),
                Map.entry("mfa_passkey", WebAuthnAuthenticationFilter.class));
        return new SecurityFilterChainRegistrar(contexaFactorFilterProvider, stepFilterClasses);
    }

    @Bean(name = "contexaFlowContextFactory")
    @ConditionalOnMissingBean
    public FlowContextFactory flowContextFactory(ApplicationContext applicationContext) {
        return new FlowContextFactory(applicationContext);
    }

    @Bean(name = "contexaSecurityPlatform")
    @ConditionalOnMissingBean
    public SecurityPlatform securityPlatform(PlatformContext context,
            ObjectProvider<SecurityConfigurer> allRegisteredConfigurersProvider,
            AdapterRegistry contexaAdapterRegistry,
            PlatformContextInitializer contexaPlatformContextInitializer,
            SecurityFilterChainRegistrar contexaSecurityFilterChainRegistrar,
            FlowContextFactory contexaFlowContextFactory,
            PlatformConfig platformConfig) {
        contexaPlatformContextInitializer.initializeSharedObjects();

        DefaultSecurityConfigurerProvider configurerProvider = new DefaultSecurityConfigurerProvider(
                allRegisteredConfigurersProvider, contexaAdapterRegistry);

        return new SecurityPlatformInitializer(
                context,
                platformConfig,
                contexaSecurityFilterChainRegistrar,
                contexaFlowContextFactory,
                new SecurityConfigurerOrchestrator(configurerProvider));
    }

    @Bean(name = "contexaPlatformBootstrap")
    @ConditionalOnMissingBean
    public PlatformBootstrap platformBootstrap(SecurityPlatform contexaSecurityPlatform,
            PlatformConfig platformConfig,
            AdapterRegistry registry,
            DslValidator contexaDslValidator,
            BridgeProperties bridgeProperties,
            ObjectProvider<SecurityConfigurer> securityConfigurerProvider) {
        securityConfigurerProvider.orderedStream().forEach(configurer -> {
            if (log.isDebugEnabled()) {
                log.debug("Materialized security configurer before platform bootstrap: {}",
                        configurer.getClass().getSimpleName());
            }
        });
        return new PlatformBootstrap(contexaSecurityPlatform, platformConfig, registry, contexaDslValidator, bridgeProperties);
    }

    @Bean(name = "contexaAuthResponseWriter")
    @ConditionalOnMissingBean
    public AuthResponseWriter authResponseWriter(@Qualifier("contexaObjectMapper") ObjectMapper objectMapper) {
        return new JsonAuthResponseWriter(objectMapper);
    }

    @Bean(name = "contexaChallengeMfaInitializer")
    @ConditionalOnMissingBean
    public ChallengeMfaInitializer challengeMfaInitializer(
            MfaSessionRepository sessionRepository,
            MfaStateMachineIntegrator stateMachineIntegrator,
            MfaPolicyProvider mfaPolicyProvider,
            PlatformConfig platformConfig) {
        return new ChallengeMfaInitializer(
                sessionRepository, stateMachineIntegrator, mfaPolicyProvider, platformConfig);
    }

    @Bean(name = "contexaZeroTrustChallengeFilter")
    @ConditionalOnMissingBean
    public ZeroTrustChallengeFilter zeroTrustChallengeFilter(
            ChallengeMfaInitializer contexaChallengeMfaInitializer,
            AuthResponseWriter responseWriter,
            AuthUrlProvider contexaAuthUrlProvider,
            MfaSessionRepository sessionRepository,
            MfaStateMachineIntegrator stateMachineIntegrator,
            DistributedLockService lockService,
            MfaFlowUrlRegistry contexaMfaFlowUrlRegistry,
            ZeroTrustActionRepository actionRepository,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ObjectProvider<UnanalysedRequestRecorder> unanalysedRequestRecorder,
            ObjectProvider<AgentConfirmationService> agentConfirmations,
            ObjectProvider<DelegationRegistry> delegationRegistry,
            ObjectProvider<AgentScopeService> agentScopes,
            ObjectProvider<AgentCallGuard> agentCallGuard,
            ObjectProvider<BridgeProperties> bridgeProperties,
            ObjectProvider<HostOwnedStepUp> hostOwnedStepUp) {

        ZeroTrustChallengeFilter filter = new ZeroTrustChallengeFilter(
                contexaChallengeMfaInitializer, responseWriter, contexaAuthUrlProvider,
                sessionRepository, stateMachineIntegrator, lockService, contexaMfaFlowUrlRegistry, actionRepository,
                securityZeroTrustProperties);
        filter.setUnanalysedRequestRecorder(unanalysedRequestRecorder.getIfAvailable());
        // Ownership design Q-5: a stored CHALLENGE is enforced under ENFORCE only.
        filter.setEnforcing(securityZeroTrustProperties::isEnforcementEnabled);
        // Ownership design S-1/S-2: when the application owns sign-in, a CHALLENGE goes to Contexa's step-up.
        if (hostOwned(bridgeProperties)) {
            filter.setHostOwnedStepUp(hostOwnedStepUp.getIfAvailable());
        }
        // docs/agent A5-2, A5-9, F-2: agents' requests meet their accountable person's confirmation.
        AgentConfirmationService confirmations = agentConfirmations.getIfAvailable();
        if (confirmations != null) {
            SecurityZeroTrustProperties.AgentSettings agent = securityZeroTrustProperties.getAgent();
            AgentConfirmationGate gate = new AgentConfirmationGate(confirmations, actionRepository, responseWriter,
                    agent.getConfirmationMaxBodyBytes(), agent.getConfirmationLinkBaseUrl(), null);
            gate.setDelegationRegistry(delegationRegistry.getIfAvailable());
            // docs/agent A5-4: a request outside an agent's narrowed scope is refused.
            gate.setScopes(agentScopes.getIfAvailable());
            // docs/agent A5-7: the call limits and the denial alarm of agents.
            gate.setCallGuard(agentCallGuard.getIfAvailable());
            // docs/agent G-9: in the report-only mode the gate records and lets the request on.
            gate.setEnforcing(securityZeroTrustProperties::isEnforcementEnabled);
            filter.setAgentConfirmationGate(gate);
        }
        return filter;
    }

    /**
     * Under CONTEXA_OWNED the filter runs inside Contexa's chain only. Under HOST_OWNED Contexa builds no chain, so it
     * runs as a servlet filter right after the application's Spring Security chain (ownership design S-1).
     */
    @Bean(name = "contexaZeroTrustChallengeFilterRegistrationBean")
    @ConditionalOnBean(ZeroTrustChallengeFilter.class)
    public FilterRegistrationBean<ZeroTrustChallengeFilter> zeroTrustChallengeFilterRegistrationBean(
            ZeroTrustChallengeFilter contexaZeroTrustChallengeFilter,
            ObjectProvider<BridgeProperties> bridgeProperties,
            ObjectProvider<SecurityProperties> securityProperties) {
        FilterRegistrationBean<ZeroTrustChallengeFilter> registrationBean =
                new FilterRegistrationBean<>(contexaZeroTrustChallengeFilter);
        registrationBean.setName("contexaZeroTrustChallengeFilter");
        return HostOwnedEnforcementOrder.enforcement(registrationBean, hostOwned(bridgeProperties),
                HostOwnedEnforcementOrder.securityFilterOrder(securityProperties), HostOwnedEnforcementOrder.CHALLENGE);
    }

    /** Whether the application owns sign-in (HOST_OWNED); Contexa then builds no chain. */
    private static boolean hostOwned(ObjectProvider<BridgeProperties> bridgeProperties) {
        BridgeProperties properties = bridgeProperties != null ? bridgeProperties.getIfAvailable() : null;
        return properties != null && properties.ownershipBehaviour().enforcesFromServletFilters();
    }

    @Bean(name = "contexaZeroTrustChallengeConfigurer")
    @ConditionalOnMissingBean
    public ZeroTrustChallengeConfigurer zeroTrustChallengeConfigurer(
            ZeroTrustChallengeFilter contexaZeroTrustChallengeFilter) {
        return new ZeroTrustChallengeConfigurer(contexaZeroTrustChallengeFilter);
    }

    @Bean(name = "contexaZeroTrustAccessControlFilter")
    @ConditionalOnMissingBean
    public ZeroTrustAccessControlFilter zeroTrustAccessControlFilter(
            ZeroTrustActionRepository actionRedisRepository,
            AuthResponseWriter responseWriter,
            IBlockedUserRecorder contexaBlockedUserRecorder,
            ChallengeMfaInitializer contexaChallengeMfaInitializer,
            AuthUrlProvider contexaAuthUrlProvider,
            BlockingSignalBroadcaster contexaBlockingDecisionRegistry,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            MfaFlowUrlRegistry contexaMfaFlowUrlRegistry,
            ObjectProvider<UnanalysedRequestRecorder> unanalysedRequestRecorder,
            ObjectProvider<AgentContainmentService> agentContainment,
            ObjectProvider<BridgeProperties> bridgeProperties,
            ObjectProvider<HostOwnedStepUp> hostOwnedStepUp) {
        ZeroTrustAccessControlFilter filter = new ZeroTrustAccessControlFilter(actionRedisRepository, responseWriter,
                contexaBlockedUserRecorder, contexaChallengeMfaInitializer, contexaAuthUrlProvider, contexaBlockingDecisionRegistry,
                securityZeroTrustProperties.getMaxBlockMfaAttempts(), contexaMfaFlowUrlRegistry);
        filter.setUnanalysedRequestRecorder(unanalysedRequestRecorder.getIfAvailable());
        // Ownership design Q-5: a stored BLOCK or ESCALATE is enforced under ENFORCE only.
        filter.setEnforcing(securityZeroTrustProperties::isEnforcementEnabled);
        filter.setMonitoringHeaders(securityZeroTrustProperties.isMonitoringHeaders());
        // docs/agent A5-3: an agent whose escalation turns into a block is stopped.
        agentContainment.ifAvailable(filter::setAgentContainment);
        // Ownership design S-1/S-2: when the application owns sign-in, a BLOCK's release by MFA goes to the step-up.
        if (hostOwned(bridgeProperties)) {
            filter.setHostOwnedStepUp(hostOwnedStepUp.getIfAvailable());
        }
        return filter;
    }

    @Bean(name = "contexaZeroTrustAccessControlFilterRegistrationBean")
    @ConditionalOnBean(ZeroTrustAccessControlFilter.class)
    public FilterRegistrationBean<ZeroTrustAccessControlFilter> zeroTrustAccessControlFilterRegistrationBean(
            ZeroTrustAccessControlFilter contexaZeroTrustAccessControlFilter,
            ObjectProvider<BridgeProperties> bridgeProperties,
            ObjectProvider<SecurityProperties> securityProperties) {
        FilterRegistrationBean<ZeroTrustAccessControlFilter> registrationBean =
                new FilterRegistrationBean<>(contexaZeroTrustAccessControlFilter);
        registrationBean.setName("contexaZeroTrustAccessControlFilter");
        return HostOwnedEnforcementOrder.enforcement(registrationBean, hostOwned(bridgeProperties),
                HostOwnedEnforcementOrder.securityFilterOrder(securityProperties),
                HostOwnedEnforcementOrder.ACCESS_CONTROL);
    }

    @Bean(name = "contexaZeroTrustAccessControlConfigurer")
    @ConditionalOnMissingBean
    @ConditionalOnBean(ZeroTrustAccessControlFilter.class)
    public ZeroTrustAccessControlConfigurer zeroTrustAccessControlConfigurer(
            ZeroTrustAccessControlFilter contexaZeroTrustAccessControlFilter) {
        return new ZeroTrustAccessControlConfigurer(contexaZeroTrustAccessControlFilter);
    }

    @Bean(name = "contexaMfaPendingAccessControlFilter")
    @ConditionalOnMissingBean
    public MfaPendingAccessControlFilter mfaPendingAccessControlFilter(
            AuthUrlProvider contexaAuthUrlProvider,
            MfaFlowUrlRegistry contexaMfaFlowUrlRegistry,
            MfaSessionRepository contexaMfaSessionRepository,
            AuthResponseWriter contexaAuthResponseWriter,
            Environment environment) {
        String errorPath = environment.getProperty("server.error.path",
                environment.getProperty("error.path", "/error"));
        return new MfaPendingAccessControlFilter(contexaAuthUrlProvider, contexaMfaFlowUrlRegistry,
                contexaMfaSessionRepository, contexaAuthResponseWriter, errorPath);
    }

    @Bean(name = "contexaMfaPendingAccessControlFilterRegistrationBean")
    @ConditionalOnBean(MfaPendingAccessControlFilter.class)
    public FilterRegistrationBean<MfaPendingAccessControlFilter> mfaPendingAccessControlFilterRegistrationBean(
            MfaPendingAccessControlFilter contexaMfaPendingAccessControlFilter) {
        FilterRegistrationBean<MfaPendingAccessControlFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(contexaMfaPendingAccessControlFilter);
        registrationBean.setEnabled(false);
        return registrationBean;
    }

    @Bean(name = "contexaMfaPendingAccessControlConfigurer")
    @ConditionalOnMissingBean
    @ConditionalOnBean(MfaPendingAccessControlFilter.class)
    public MfaPendingAccessControlConfigurer mfaPendingAccessControlConfigurer(
            MfaPendingAccessControlFilter contexaMfaPendingAccessControlFilter) {
        return new MfaPendingAccessControlConfigurer(contexaMfaPendingAccessControlFilter);
    }

    @Bean(name = "contexaHttpSessionCleanupListener")
    @ConditionalOnMissingBean
    public HttpSessionCleanupListener httpSessionCleanupListener(
            ObjectProvider<ZeroTrustSecurityService> zeroTrustSecurityService,
            ObjectProvider<MfaSessionRepository> mfaSessionRepository,
            ObjectProvider<MfaStateMachineService> mfaStateMachineService) {
        return new HttpSessionCleanupListener(zeroTrustSecurityService, mfaSessionRepository, mfaStateMachineService);
    }
}
