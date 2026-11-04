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

import io.contexa.contexacommon.operating.ConditionalOnOwnership;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.handler.MfaFactorProcessingSuccessHandler;
import io.contexa.contexaidentity.security.handler.PrimaryAuthenticationSuccessHandler;
import io.contexa.contexaidentity.security.handler.UnifiedAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import org.springframework.beans.factory.annotation.Autowired;
import io.contexa.contexaidentity.security.core.bootstrap.WebSecurityConfigurationDependencyInjector;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import java.util.UUID;

/** What the sign-in of Contexa needs: its handlers, and the chain that keeps Boot's default chain away. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnOwnership(SecurityOwnershipMode.CONTEXA_OWNED)
public class IdentitySecurityCoreContexaOwnedConfiguration {

    /** The chain that only keeps Boot's default chain away where Contexa owns the sign-in; it matches no request. */
    public static final String PLACEHOLDER_CHAIN = "contexaPlaceholderSecurityFilterChain";

    @Bean(name = PLACEHOLDER_CHAIN)
    @ConditionalOnMissingBean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.securityMatcher("/" + UUID.randomUUID())
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return httpSecurity.build();
    }

    @Bean(name = "contexaWebSecurityConfigurationDependencyInjector")
    @ConditionalOnMissingBean
    public WebSecurityConfigurationDependencyInjector webSecurityConfigurationDependencyInjector() {
        return new WebSecurityConfigurationDependencyInjector();
    }

    @Bean(name = "contexaPrimaryAuthenticationSuccessHandler")
    @ConditionalOnMissingBean
    public PrimaryAuthenticationSuccessHandler primaryAuthenticationSuccessHandler(
            AuthResponseWriter contexaAuthResponseWriter,
            MfaPolicyProvider mfaPolicyProvider,
            ApplicationContext applicationContext,
            MfaStateMachineIntegrator contexaMfaStateMachineIntegrator,
            MfaSessionRepository contexaMfaSessionRepository,
            AuthUrlProvider contexaAuthUrlProvider,
            MfaFlowUrlRegistry contexaMfaFlowUrlRegistry,
            TokenService tokenService,
            AuthContextProperties authContextProperties,
            ZeroTrustEventPublisher contexaZeroTrustEventPublisher,
            ZeroTrustActionRepository actionRedisRepository,
            SecurityLearningService contexaSecurityLearningService,
            IBlockedUserRecorder contexaBlockedUserRecorder,
            BlockMfaStateStore blockMfaStateStore,
            CentralAuditFacade contexaCentralAuditFacade,
            BlockingSignalBroadcaster blockingSignalBroadcaster,
            @Autowired(required = false) LoginPolicyHandler contexaLoginPolicyHandler) {
        return new PrimaryAuthenticationSuccessHandler(mfaPolicyProvider, tokenService, contexaAuthResponseWriter,
                authContextProperties, applicationContext, contexaMfaStateMachineIntegrator, contexaMfaSessionRepository,
                contexaAuthUrlProvider, contexaMfaFlowUrlRegistry, contexaZeroTrustEventPublisher, actionRedisRepository, contexaSecurityLearningService,
                contexaBlockedUserRecorder, blockMfaStateStore, contexaCentralAuditFacade, blockingSignalBroadcaster, contexaLoginPolicyHandler);
    }

    @Bean(name = "contexaUnifiedAuthenticationFailureHandler")
    @ConditionalOnMissingBean
    public UnifiedAuthenticationFailureHandler unifiedAuthenticationFailureHandler(
            MfaStateMachineIntegrator contexaMfaStateMachineIntegrator,
            AuthResponseWriter contexaAuthResponseWriter,
            MfaSessionRepository contexaMfaSessionRepository,
            ZeroTrustActionRepository actionRedisRepository,
            AuthContextProperties authContextProperties,
            IBlockedUserRecorder contexaBlockedUserRecorder,
            @Autowired(required = false) CentralAuditFacade contexaCentralAuditFacade,
            @Autowired(required = false) LoginPolicyHandler contexaLoginPolicyHandler,
            @Autowired(required = false) SecurityContextDataStore securityContextDataStore) {
        return new UnifiedAuthenticationFailureHandler(contexaAuthResponseWriter, contexaMfaStateMachineIntegrator,
                contexaMfaSessionRepository, actionRedisRepository, authContextProperties.getMfa(),
                contexaBlockedUserRecorder, contexaCentralAuditFacade, contexaLoginPolicyHandler, securityContextDataStore);
    }

    @Bean(name = "contexaMfaFactorProcessingSuccessHandler")
    @ConditionalOnMissingBean
    public MfaFactorProcessingSuccessHandler mfaFactorProcessingSuccessHandler(
            MfaStateMachineIntegrator contexaMfaStateMachineIntegrator,
            AuthResponseWriter contexaAuthResponseWriter,
            MfaSessionRepository contexaMfaSessionRepository,
            AuthUrlProvider contexaAuthUrlProvider,
            MfaFlowUrlRegistry contexaMfaFlowUrlRegistry,
            AuthContextProperties authContextProperties,
            TokenService tokenService,
            ZeroTrustEventPublisher contexaZeroTrustEventPublisher,
            ZeroTrustActionRepository actionRedisRepository,
            SecurityLearningService contexaSecurityLearningService,
            ApplicationContext applicationContext,
            IBlockedUserRecorder contexaBlockedUserRecorder,
            BlockMfaStateStore blockMfaStateStore,
            CentralAuditFacade contexaCentralAuditFacade,
            BlockingSignalBroadcaster blockingSignalBroadcaster) {
        return new MfaFactorProcessingSuccessHandler(contexaMfaStateMachineIntegrator, contexaAuthResponseWriter,
                authContextProperties, contexaMfaSessionRepository, tokenService, contexaAuthUrlProvider,
                contexaMfaFlowUrlRegistry, contexaZeroTrustEventPublisher, actionRedisRepository, contexaSecurityLearningService, applicationContext,
                contexaBlockedUserRecorder, blockMfaStateStore, contexaCentralAuditFacade, blockingSignalBroadcaster);
    }
}
