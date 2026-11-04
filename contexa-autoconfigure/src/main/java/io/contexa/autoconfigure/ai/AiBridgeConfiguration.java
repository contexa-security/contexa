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
package io.contexa.autoconfigure.ai;

import java.util.Locale;
import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexacommon.annotation.AiSecurityImportSelector;
import io.contexa.contexacommon.security.bridge.*;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageEvaluator;
import io.contexa.contexacommon.security.bridge.handoff.ContexaAuthBridge;
import io.contexa.contexacommon.security.bridge.handoff.ContexaAuthBridgeHandler;
import io.contexa.contexacommon.security.bridge.handoff.DefaultContexaAuthBridgeHandler;
import io.contexa.contexacommon.security.bridge.resolver.*;
import io.contexa.contexacommon.security.bridge.runtime.BridgeRuntimeSupport;
import io.contexa.contexacommon.security.bridge.runtime.RequestPathDatabaseGuard;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextCollector;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncService;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexacommon.security.network.ClientIpResolutionPolicy;
import io.contexa.contexacore.security.AISessionSecurityContextRepository;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.List;

@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(SecurityFilterChain.class)
@EnableConfigurationProperties(BridgeProperties.class)
public class AiBridgeConfiguration {

    @Bean(name = "contexaRequestContextCollector")
    @ConditionalOnMissingBean
    public RequestContextCollector requestContextCollector(BridgeProperties properties) {
        BridgeProperties.Network network = properties.getNetwork();
        return new RequestContextCollector(ClientIpResolutionPolicy.of(
                network.isTrustedProxyValidationEnabled(),
                network.getTrustedProxies()
        ));
    }

    @Bean(name = "contexaBridgeCoverageEvaluator")
    @ConditionalOnMissingBean
    public BridgeCoverageEvaluator bridgeCoverageEvaluator() {
        return new BridgeCoverageEvaluator();
    }

    @Bean(name = "contexaAuthBridge")
    @ConditionalOnMissingBean(AuthBridge.class)
    public AuthBridge authBridge(BridgeProperties properties, Environment environment) {
        BridgeProperties.Session sessionProperties = properties.getAuthentication().getSession();
        BridgeProperties.RequestAttributes requestAttributes = properties.getAuthentication().getRequestAttributes();
        applyAuthObjectHints(sessionProperties, requestAttributes, environment);

        SessionAuthBridge sessionAuthBridge = new SessionAuthBridge(sessionProperties);
        RequestAttributeAuthBridge requestAttributeAuthBridge = new RequestAttributeAuthBridge(requestAttributes);
        HeaderAuthBridge headerAuthBridge = new HeaderAuthBridge(properties);

        List<AuthBridge> bridges = new ArrayList<>();
        AuthObjectLocation location = resolveAuthObjectLocation(environment);
        if (location == AuthObjectLocation.REQUEST_ATTRIBUTE) {
            bridges.add(requestAttributeAuthBridge);
            bridges.add(sessionAuthBridge);
            bridges.add(headerAuthBridge);
        } else if (location == AuthObjectLocation.HEADER) {
            bridges.add(headerAuthBridge);
            bridges.add(sessionAuthBridge);
            bridges.add(requestAttributeAuthBridge);
        } else {
            bridges.add(sessionAuthBridge);
            bridges.add(requestAttributeAuthBridge);
            bridges.add(headerAuthBridge);
        }
        return new CompositeAuthBridge(bridges);
    }

    @Bean(name = "contexaSecurityOnAuthenticationStampResolver")
    @Order(0)
    @ConditionalOnMissingBean(SecurityContextAuthenticationStampResolver.class)
    public AuthenticationStampResolver securityOnAuthenticationStampResolver(
            ObjectProvider<AgentClientDirectory> agentClientDirectory) {
        return new SecurityContextAuthenticationStampResolver(
                agentClientDirectory.getIfAvailable(() -> AgentClientDirectory.NONE));
    }

    @Bean(name = "contexaSecurityOffBridgeAuthenticationStampResolver")
    @Order(5)
    @ConditionalOnMissingBean(AuthBridgeAuthenticationStampResolver.class)
    public AuthenticationStampResolver securityOffBridgeAuthenticationStampResolver(AuthBridge contexaAuthBridge) {
        return new AuthBridgeAuthenticationStampResolver(contexaAuthBridge);
    }

    @Bean(name = "contexaSecurityOnAuthorizationStampResolver")
    @Order(0)
    @ConditionalOnMissingBean(SecurityContextAuthorizationStampResolver.class)
    public AuthorizationStampResolver securityOnAuthorizationStampResolver() {
        return new SecurityContextAuthorizationStampResolver();
    }

    @Bean(name = "contexaSecurityOffSessionAuthorizationStampResolver")
    @Order(5)
    @ConditionalOnMissingBean(SessionAuthorizationStampResolver.class)
    public AuthorizationStampResolver securityOffSessionAuthorizationStampResolver() {
        return new SessionAuthorizationStampResolver();
    }

    @Bean(name = "contexaSecurityOffRequestAttributeAuthorizationStampResolver")
    @Order(10)
    @ConditionalOnMissingBean(RequestAttributeAuthorizationStampResolver.class)
    public AuthorizationStampResolver securityOffRequestAttributeAuthorizationStampResolver() {
        return new RequestAttributeAuthorizationStampResolver();
    }

    @Bean(name = "contexaSecurityOffHeaderAuthorizationStampResolver")
    @Order(20)
    @ConditionalOnMissingBean(HeaderAuthorizationStampResolver.class)
    public AuthorizationStampResolver securityOffHeaderAuthorizationStampResolver() {
        return new HeaderAuthorizationStampResolver();
    }

    /**
     * A1-1: the delegation an access token states comes first, since the authorization server signed it; a token that
     * names no agent yields no stamp and the session, request attribute and header channels decide as before.
     */
    @Bean(name = "contexaTokenDelegationStampResolver")
    @Order(1)
    @ConditionalOnMissingBean(TokenDelegationStampResolver.class)
    public DelegationStampResolver tokenDelegationStampResolver(ObjectProvider<AgentClientDirectory> agentClientDirectory) {
        // A1-2: a client the agent registry approves is read as that agent even when its token carries no agent claim.
        return new TokenDelegationStampResolver(agentClientDirectory.getIfAvailable(() -> AgentClientDirectory.NONE));
    }

    @Bean(name = "contexaSecurityOffSessionDelegationStampResolver")
    @Order(5)
    @ConditionalOnMissingBean(SessionDelegationStampResolver.class)
    public DelegationStampResolver securityOffSessionDelegationStampResolver() {
        return new SessionDelegationStampResolver();
    }

    @Bean(name = "contexaSecurityOffRequestAttributeDelegationStampResolver")
    @Order(10)
    @ConditionalOnMissingBean(RequestAttributeDelegationStampResolver.class)
    public DelegationStampResolver securityOffRequestAttributeDelegationStampResolver() {
        return new RequestAttributeDelegationStampResolver();
    }

    @Bean(name = "contexaSecurityOffHeaderDelegationStampResolver")
    @Order(20)
    @ConditionalOnMissingBean(HeaderDelegationStampResolver.class)
    public DelegationStampResolver securityOffHeaderDelegationStampResolver() {
        return new HeaderDelegationStampResolver();
    }

    /** A1-11: the token claim names the agent session key reads, registered for every filter of a request. */
    @Bean(name = "contexaAgentSessionKeyRegistrar")
    @ConditionalOnMissingBean
    public AgentSessionKeyRegistrar agentSessionKeyRegistrar(BridgeProperties bridgeProperties) {
        return new AgentSessionKeyRegistrar(bridgeProperties);
    }

    /**
     * A1-13: last, an approved agent signed in with its own account (a session login) is that agent; no other channel
     * stated an agent by then, and a person's account yields nothing.
     */
    @Bean(name = "contexaAgentAccountDelegationStampResolver")
    @Order(30)
    @ConditionalOnMissingBean(AgentAccountDelegationStampResolver.class)
    public DelegationStampResolver agentAccountDelegationStampResolver(ObjectProvider<AgentClientDirectory> agentClientDirectory) {
        return new AgentAccountDelegationStampResolver(agentClientDirectory.getIfAvailable(() -> AgentClientDirectory.NONE));
    }

    // BridgeUserMirrorSyncService is provided by AiBridgeUserMirrorSyncAutoConfiguration, which is evaluated
    // after the Contexa repositories are registered. It is resolved through ObjectProvider at instantiation time.
    @Bean(name = "contexaBridgeRuntimeSupport")
    @ConditionalOnMissingBean
    public BridgeRuntimeSupport bridgeRuntimeSupport(
            BridgeProperties properties,
            ObjectProvider<BridgeUserMirrorSyncService> bridgeUserMirrorSyncService,
            RequestPathDatabaseGuard contexaRequestPathDatabaseGuard) {
        return new BridgeRuntimeSupport(properties, bridgeUserMirrorSyncService.getIfAvailable(), contexaRequestPathDatabaseGuard);
    }

    /** An outage of Contexa's database must not hold the application's request threads. */
    @Bean(name = "contexaRequestPathDatabaseGuard")
    @ConditionalOnMissingBean
    public RequestPathDatabaseGuard requestPathDatabaseGuard() {
        return new RequestPathDatabaseGuard();
    }

    @Bean
    @ConditionalOnMissingBean
    public ContexaAuthBridgeHandler contexaAuthBridgeHandler(
            BridgeProperties properties,
            RequestContextCollector contexaRequestContextCollector,
            BridgeCoverageEvaluator contexaBridgeCoverageEvaluator,
            BridgeRuntimeSupport contexaBridgeRuntimeSupport,
            ObjectProvider<AISessionSecurityContextRepository> aiSessionSecurityContextRepository) {
        return new DefaultContexaAuthBridgeHandler(
                properties,
                contexaRequestContextCollector,
                contexaBridgeCoverageEvaluator,
                contexaBridgeRuntimeSupport,
                aiSessionSecurityContextRepository.getIfAvailable()
        );
    }

    @Bean("contexaAuthBridgeBinding")
    @ConditionalOnMissingBean(name = "contexaAuthBridgeBinding")
    public DisposableBean contexaAuthBridgeBinding(ContexaAuthBridgeHandler contexaAuthBridgeHandler) {
        ContexaAuthBridge.registerHandler(contexaAuthBridgeHandler);
        return ContexaAuthBridge::clearHandler;
    }

    @Bean(name = "contexaBridgeResolutionFilter")
    @ConditionalOnMissingBean
    public BridgeResolutionFilter bridgeResolutionFilter(
            BridgeProperties properties,
            RequestContextCollector contexaRequestContextCollector,
            ObjectProvider<AuthenticationStampResolver> authenticationStampResolvers,
            ObjectProvider<AuthorizationStampResolver> authorizationStampResolvers,
            ObjectProvider<DelegationStampResolver> delegationStampResolvers,
            BridgeCoverageEvaluator contexaBridgeCoverageEvaluator,
            ObjectProvider<BridgeUserMirrorSyncService> bridgeUserMirrorSyncService,
            BridgeRuntimeSupport contexaBridgeRuntimeSupport) {
        return new BridgeResolutionFilter(
                properties,
                contexaRequestContextCollector,
                authenticationStampResolvers.orderedStream().toList(),
                authorizationStampResolvers.orderedStream().toList(),
                delegationStampResolvers.orderedStream().toList(),
                contexaBridgeCoverageEvaluator,
                bridgeUserMirrorSyncService.getIfAvailable(),
                contexaBridgeRuntimeSupport,
                null
        );
    }

    /**
     * The bridge's servlet registration. Under HOST_OWNED it runs right after the application's Spring Security chain,
     * before Contexa's enforcement filters, which read the delegation it stamps; under CONTEXA_OWNED it keeps the order
     * it always had (it also runs first inside Contexa's chain).
     */
    @Bean(name = "contexaBridgeResolutionFilterRegistration")
    @ConditionalOnMissingBean(name = "contexaBridgeResolutionFilterRegistration")
    public FilterRegistrationBean<BridgeResolutionFilter> bridgeResolutionFilterRegistration(
            BridgeResolutionFilter contexaBridgeResolutionFilter,
            BridgeProperties properties,
            ObjectProvider<SecurityProperties> securityProperties) {
        FilterRegistrationBean<BridgeResolutionFilter> registration = new FilterRegistrationBean<>(contexaBridgeResolutionFilter);
        registration.setName("contexaBridgeResolutionFilter");
        return HostOwnedEnforcementOrder.bridge(registration, properties.ownershipBehaviour().enforcesFromServletFilters(),
                HostOwnedEnforcementOrder.securityFilterOrder(securityProperties));
    }

    private void applyAuthObjectHints(
            BridgeProperties.Session sessionProperties,
            BridgeProperties.RequestAttributes requestAttributes,
            Environment environment) {
        String authObjectType = resolveAuthObjectType(environment);
        if (authObjectType != null) {
            sessionProperties.setObjectTypeName(authObjectType);
            requestAttributes.setObjectTypeName(authObjectType);
        }

        String authObjectAttribute = resolveAuthObjectAttribute(environment);
        if (authObjectAttribute == null) {
            return;
        }

        AuthObjectLocation location = resolveAuthObjectLocation(environment);
        if (location == AuthObjectLocation.SESSION) {
            sessionProperties.setAttribute(authObjectAttribute);
        } else if (location == AuthObjectLocation.REQUEST_ATTRIBUTE) {
            requestAttributes.setAttribute(authObjectAttribute);
        }
    }

    private AuthObjectLocation resolveAuthObjectLocation(Environment environment) {
        String configured = environment.getProperty(AiSecurityImportSelector.PROP_AUTH_OBJECT_LOCATION);
        if (configured == null || configured.isBlank()) {
            return AuthObjectLocation.AUTO;
        }
        try {
            return AuthObjectLocation.valueOf(configured.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ignored) {
            return AuthObjectLocation.AUTO;
        }
    }

    private String resolveAuthObjectAttribute(Environment environment) {
        String configured = environment.getProperty(AiSecurityImportSelector.PROP_AUTH_OBJECT_ATTRIBUTE);
        if (configured == null) {
            return null;
        }
        String normalized = configured.trim();
        return normalized.isBlank() ? null : normalized;
    }

    private String resolveAuthObjectType(Environment environment) {
        String configured = environment.getProperty(AiSecurityImportSelector.PROP_AUTH_OBJECT_TYPE);
        if (configured == null) {
            return null;
        }
        String normalized = configured.trim();
        if (normalized.isBlank() || Object.class.getName().equals(normalized)) {
            return null;
        }
        return normalized;
    }
}
