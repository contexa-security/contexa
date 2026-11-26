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

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.BooleanSupplier;
import java.util.stream.Stream;
import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexacommon.security.bridge.*;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageEvaluator;
import io.contexa.contexacommon.security.bridge.identity.IdentityDiagnostics;
import io.contexa.contexacommon.security.bridge.identity.IdentityResolution;
import io.contexa.contexacommon.security.bridge.subject.ContexaBridge;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubjectMapper;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubjectResolver;
import io.contexa.contexacommon.security.bridge.subject.ContexaUsers;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.event.support.HostSignInEvents;
import io.contexa.contexacore.autonomous.service.UserEngineStatePurger;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import io.contexa.contexacore.security.session.SessionIdResolver;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import io.contexa.contexaiam.admin.web.auth.service.SessionManagementService;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserEmailProvider;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.lang.Nullable;
import io.contexa.contexacommon.security.bridge.resolver.*;
import io.contexa.contexacommon.security.bridge.runtime.BridgeRuntimeSupport;
import io.contexa.contexacommon.security.bridge.runtime.RequestPathDatabaseGuard;
import io.contexa.contexacommon.store.ContexaStores;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextCollector;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncService;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexacommon.security.network.ClientIpResolutionPolicy;
import io.contexa.contexacore.security.ContexaUserStore;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.source.ConfigurationPropertyName;
import org.springframework.boot.context.properties.source.ConfigurationPropertySource;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.context.properties.source.IterableConfigurationPropertySource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(SecurityFilterChain.class)
@EnableConfigurationProperties(BridgeProperties.class)
public class AiBridgeConfiguration {

    /**
     * bridge v2 B6: the settings of the bridge's old channels, which no code reads any more: a session attribute, the
     * flat request attributes and the headers, for the user, for its authorization and for its delegation, and the hint
     * {@code @EnableAISecurity} once published for where the legacy object lay. The {@code security-context} keys and
     * {@code contexa.bridge.delegation.token.*} are still read and are not among them.
     */
    static final List<ConfigurationPropertyName> REMOVED_SETTINGS = Stream.of(
                    "contexa.ai.security.auth-object",
                    "contexa.bridge.authentication.session",
                    "contexa.bridge.authentication.request-attributes",
                    "contexa.bridge.authentication.headers",
                    "contexa.bridge.authorization.session",
                    "contexa.bridge.authorization.request-attributes",
                    "contexa.bridge.authorization.headers",
                    "contexa.bridge.delegation.session",
                    "contexa.bridge.delegation.request-attributes",
                    "contexa.bridge.delegation.headers")
            .map(ConfigurationPropertyName::of)
            .toList();

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

    @Bean(name = "contexaSecurityOnAuthenticationStampResolver")
    @Order(0)
    @ConditionalOnMissingBean(SecurityContextAuthenticationStampResolver.class)
    public AuthenticationStampResolver securityOnAuthenticationStampResolver(
            ObjectProvider<AgentClientDirectory> agentClientDirectory) {
        return new SecurityContextAuthenticationStampResolver(
                agentClientDirectory.getIfAvailable(() -> AgentClientDirectory.NONE));
    }

    @Bean(name = "contexaSecurityOnAuthorizationStampResolver")
    @Order(0)
    @ConditionalOnMissingBean(SecurityContextAuthorizationStampResolver.class)
    public AuthorizationStampResolver securityOnAuthorizationStampResolver() {
        return new SecurityContextAuthorizationStampResolver();
    }

    /**
     * A1-1: the delegation an access token states comes first, since the authorization server signed it; a token that
     * names no agent yields no stamp, and an approved agent's own account is asked last. A1-2: a client the agent
     * registry approves is read as that agent even when its token carries no agent claim.
     */
    @Bean(name = "contexaTokenDelegationStampResolver")
    @Order(1)
    @ConditionalOnMissingBean(TokenDelegationStampResolver.class)
    public DelegationStampResolver tokenDelegationStampResolver(ObjectProvider<AgentClientDirectory> agentClientDirectory) {
        return new TokenDelegationStampResolver(agentClientDirectory.getIfAvailable(() -> AgentClientDirectory.NONE));
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

    /**
     * BridgeUserMirrorSyncService is provided by AiBridgeUserMirrorSyncAutoConfiguration, which is evaluated after the
     * Contexa repositories are registered. It is resolved through ObjectProvider at instantiation time.
     */
    @Bean(name = "contexaBridgeRuntimeSupport")
    @ConditionalOnMissingBean
    public BridgeRuntimeSupport bridgeRuntimeSupport(
            BridgeProperties properties,
            ObjectProvider<BridgeUserMirrorSyncService> bridgeUserMirrorSyncService,
            RequestPathDatabaseGuard contexaRequestPathDatabaseGuard,
            BeanFactory beanFactory) {
        BridgeRuntimeSupport support = new BridgeRuntimeSupport(properties, bridgeUserMirrorSyncService.getIfAvailable(),
                contexaRequestPathDatabaseGuard, ContexaUserStore.signsInWithContexaAccounts(beanFactory));
        support.setUserKey(ZeroTrustUserKey::of);
        return support;
    }

    /** An outage of Contexa's database must not hold the application's request threads. */
    @Bean(name = "contexaRequestPathDatabaseGuard")
    @ConditionalOnMissingBean
    public RequestPathDatabaseGuard requestPathDatabaseGuard(ObjectProvider<ContexaStores> contexaStores) {
        ContexaStores stores = contexaStores.getIfAvailable();
        return new RequestPathDatabaseGuard(stores != null ? stores.database() : null);
    }

    /**
     * bridge v2 B5-2: the optional calls of a legacy application ({@link ContexaBridge}, {@link ContexaUsers}), bound to
     * what Contexa does for its own sign-ins, sign-outs and deleted accounts, and unbound when the context closes.
     */
    @Bean("contexaBridgeApiBinding")
    @ConditionalOnMissingBean(name = "contexaBridgeApiBinding")
    public DisposableBean contexaBridgeApiBinding(
            BridgeProperties properties,
            ObjectProvider<BridgeResolutionFilter> bridgeResolutionFilter,
            ObjectProvider<ZeroTrustEventPublisher> zeroTrustEventPublisher,
            ObjectProvider<SecurityContextDataStore> securityContextDataStore,
            ObjectProvider<HostSignInEvents> hostSignInEvents,
            ObjectProvider<SessionManagementService> sessionManagementService,
            ObjectProvider<ZeroTrustSecurityService> zeroTrustSecurityService,
            ObjectProvider<SessionIdResolver> sessionIdResolver,
            ObjectProvider<UserEngineStatePurger> userEngineStatePurger,
            ObjectProvider<BridgeRuntimeSupport> bridgeRuntimeSupport) {
        ContexaBridgeApiHandler handler = new ContexaBridgeApiHandler(properties, bridgeResolutionFilter,
                zeroTrustEventPublisher, securityContextDataStore, hostSignInEvents, sessionManagementService,
                zeroTrustSecurityService, sessionIdResolver, userEngineStatePurger, bridgeRuntimeSupport);
        ContexaBridge.registerHandler(handler);
        ContexaUsers.registerHandler(handler);
        return () -> {
            ContexaBridge.clearHandler();
            ContexaUsers.clearHandler();
        };
    }

    /** bridge v2: what resolving the identities of requests came to, counted for the console and the start report. */
    @Bean(name = "contexaIdentityDiagnostics")
    @ConditionalOnMissingBean
    public IdentityDiagnostics identityDiagnostics() {
        return new IdentityDiagnostics();
    }

    /**
     * bridge v2: the one function that makes the identity of a request, from the application's declarations: its
     * {@link ContexaSubjectResolver}, its {@link ContexaSubjectMapper} and its {@link BridgeUserEmailProvider}, each at
     * most one. Two resolvers or two mappers stop the start, since Contexa would not know which one names the user.
     */
    @Bean(name = "contexaIdentityResolution")
    @ConditionalOnMissingBean
    public IdentityResolution identityResolution(
            BridgeProperties properties,
            ListableBeanFactory beanFactory,
            IdentityDiagnostics contexaIdentityDiagnostics) {
        BooleanSupplier contexaAccountsSignIn = ContexaUserStore.signsInWithContexaAccounts(beanFactory);
        IdentityResolution.Accounts accounts = authentication -> ConsoleSession.current()
                ? ContexaIdentity.subjectId(authentication)
                : ContexaAccountAuthentication.accountName(authentication, properties, contexaAccountsSignIn);
        return new IdentityResolution(
                IdentityResolution.Settings.of(properties),
                single(beanFactory, ContexaSubjectResolver.class),
                single(beanFactory, ContexaSubjectMapper.class),
                beanFactory.getBeanProvider(BridgeUserEmailProvider.class).getIfUnique(),
                accounts,
                contexaIdentityDiagnostics);
    }

    @Nullable
    private static <T> T single(ListableBeanFactory beanFactory, Class<T> type) {
        String[] names = beanFactory.getBeanNamesForType(type, true, false);
        if (names.length > 1) {
            throw new IllegalStateException("[Contexa] Bridge: the application has " + names.length + " beans of "
                    + type.getSimpleName() + " " + Arrays.toString(names) + ", and Contexa would not know which one names"
                    + " the user of a request. Keep one " + type.getSimpleName() + " bean.");
        }
        return names.length == 1 ? beanFactory.getBean(names[0], type) : null;
    }

    /**
     * bridge v2 B6 (plan 3.5, upgrade path): an installation that still sets one of the {@link #REMOVED_SETTINGS} is told
     * once at start which keys are no longer read and what names the user of a request instead. The start goes on, and
     * only the names of the keys are written, never their values.
     */
    @Bean(name = "contexaRemovedBridgeSettingsReport")
    @ConditionalOnMissingBean(name = "contexaRemovedBridgeSettingsReport")
    public SmartInitializingSingleton removedBridgeSettingsReport(Environment environment) {
        return () -> {
            List<String> removed = removedBridgeSettings(environment);
            if (!removed.isEmpty()) {
                log.error("[Contexa] Bridge: Contexa no longer reads the settings {}. Name the user of a request with a "
                        + "ContexaSubjectResolver bean, or put a ContexaSubject in the request attribute ctxa.subject "
                        + "(ContexaSubject.REQUEST_ATTRIBUTE), and remove these settings.", removed);
            }
        };
    }

    /** The keys the environment sets under one of the {@link #REMOVED_SETTINGS}, by name in order; no value is read. */
    static List<String> removedBridgeSettings(Environment environment) {
        if (!(environment instanceof ConfigurableEnvironment)) {
            return List.of();
        }
        Set<String> found = new TreeSet<>();
        try {
            for (ConfigurationPropertySource source : ConfigurationPropertySources.get(environment)) {
                if (source instanceof IterableConfigurationPropertySource names) {
                    names.stream()
                            .filter(AiBridgeConfiguration::isRemovedSetting)
                            .map(ConfigurationPropertyName::toString)
                            .forEach(found::add);
                }
            }
        } catch (RuntimeException e) {
            log.error("[Contexa] Bridge: could not look for the settings Contexa no longer reads", e);
        }
        return List.copyOf(found);
    }

    private static boolean isRemovedSetting(ConfigurationPropertyName name) {
        return REMOVED_SETTINGS.stream().anyMatch(removed -> removed.equals(name) || removed.isAncestorOf(name));
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
            BridgeRuntimeSupport contexaBridgeRuntimeSupport,
            IdentityResolution contexaIdentityResolution) {
        return new BridgeResolutionFilter(
                properties,
                contexaRequestContextCollector,
                authenticationStampResolvers.orderedStream().toList(),
                authorizationStampResolvers.orderedStream().toList(),
                delegationStampResolvers.orderedStream().toList(),
                contexaBridgeCoverageEvaluator,
                bridgeUserMirrorSyncService.getIfAvailable(),
                contexaBridgeRuntimeSupport,
                null,
                contexaIdentityResolution
        );
    }

    /**
     * The bridge's place in Contexa's filter slot (R-10 of docs/agent/운영모드-정상화-구현계획.md), whatever the mode: first,
     * right after the Spring Security filter chain, before Contexa's other filters, which read what it stamps. Under mode
     * FULL it also runs first inside Contexa's own chain; being a once-per-request filter under one name, it resolves a
     * request that chain took once.
     */
    @Bean(name = "contexaBridgeResolutionFilterRegistration")
    @ConditionalOnMissingBean(name = "contexaBridgeResolutionFilterRegistration")
    public ContexaSlotFilterRegistration<BridgeResolutionFilter> bridgeResolutionFilterRegistration(
            BridgeResolutionFilter contexaBridgeResolutionFilter,
            ObjectProvider<SecurityProperties> securityProperties) {
        return ContexaServletFilterOrder.member(contexaBridgeResolutionFilter, "contexaBridgeResolutionFilter",
                ContexaServletFilterOrder.securityFilterOrder(securityProperties), ContexaServletFilterOrder.BRIDGE);
    }
}
