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
package io.contexa.autoconfigure.iam.admin;

import org.springframework.beans.factory.BeanFactory;
import io.contexa.autoconfigure.core.ContexaOwnBeans;
import io.contexa.autoconfigure.core.autonomous.CoreAutonomousAutoConfiguration;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexacore.autonomous.agent.AgentLearningControl;
import io.contexa.contexacore.autonomous.agent.AgentRegistry;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentRegistry;
import io.contexa.contexacore.autonomous.agent.InMemoryDelegationRegistry;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.company.CompanyRecordStore;
import io.contexa.contexacore.autonomous.company.InMemoryCompanyRecordStore;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.web.agent.controller.AgentAdminController;
import io.contexa.contexaiam.admin.web.agent.controller.AgentDelegationAdminApiController;
import io.contexa.contexaiam.admin.web.agent.controller.AgentDelegationApiController;
import io.contexa.contexaiam.admin.web.agent.controller.AgentLearningApiController;
import io.contexa.contexaiam.admin.web.agent.controller.AgentRegistrationApiController;
import io.contexa.contexaiam.admin.web.agent.service.AgentDelegationService;
import io.contexa.contexaiam.admin.web.agent.service.AgentLearningAdminService;
import io.contexa.contexaiam.admin.web.agent.service.AgentProvisioning;
import io.contexa.contexaiam.admin.web.agent.service.OAuth2AgentProvisioning;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.contexaiam.admin.web.company.controller.CompanyRecordsAdminController;
import io.contexa.contexaiam.admin.web.company.controller.CompanyRecordsApiController;
import io.contexa.contexaiam.admin.web.company.service.CompanyRecordsAdminService;
import io.contexa.contexaiam.agent.JdbcAgentRegistry;
import io.contexa.contexaiam.agent.JdbcCompanyRecordStore;
import io.contexa.contexaiam.agent.JdbcDelegationRegistry;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.time.Duration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import java.util.LinkedHashMap;
import java.util.Map;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.agent.AgentNoticeChannel;
import io.contexa.contexacore.autonomous.agent.AgentNoticeStore;
import io.contexa.contexacore.autonomous.agent.AgentNotices;
import io.contexa.contexacore.autonomous.agent.AgentTokenRevoker;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentNoticeStore;
import io.contexa.contexaiam.agent.JdbcAgentNoticeStore;
import io.contexa.contexacore.autonomous.agent.AgentCallGuard;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationAuthorizer;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationExpiry;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationService;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationStore;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentConfirmationStore;
import io.contexa.contexacore.autonomous.agent.SignedAgentConfirmationAuthorizer;
import io.contexa.contexacore.verification.evidence.EvidenceSigner;
import io.contexa.contexacore.verification.evidence.HmacEvidenceSigner;
import io.contexa.contexaiam.agent.JdbcAgentConfirmationStore;
import io.contexa.contexaiam.agent.JdbcAgentScopeStore;
import io.contexa.contexacore.autonomous.agent.AgentRequestStatePurgeContributor;
import io.contexa.contexacore.autonomous.agent.AgentScopeService;
import io.contexa.contexacore.autonomous.agent.AgentScopeStore;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentScopeStore;
import io.contexa.contexaiam.agent.web.AgentConfirmationApiController;
import io.contexa.contexaiam.agent.web.AgentConfirmationController;
import io.contexa.contexaidentity.security.agent.OAuth2AgentConfirmationAuthorizer;
import io.contexa.contexacore.autonomous.agent.AgentContainmentService;
import io.contexa.contexaiam.admin.web.agent.controller.AgentStopApiController;
import io.contexa.contexaiam.admin.web.agent.controller.AgentStopController;
import io.contexa.contexaiam.admin.web.agent.service.AgentContainmentAdminService;
import io.contexa.contexaidentity.security.agent.MailAgentNoticeChannel;
import io.contexa.contexaidentity.security.agent.OAuth2AgentTokenRevoker;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.DeviceAwareOAuth2AuthorizationService;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IForceLogoutService;
import io.contexa.contexacore.autonomous.signal.RiskSignalReceiver;
import io.contexa.contexacore.autonomous.signal.SecurityEventTokenVerifier;
import io.contexa.contexacore.autonomous.service.UserEngineStatePurger;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import io.contexa.contexaiam.agent.web.RiskSignalReceiverController;
import io.contexa.contexaidentity.security.signal.JwtSecurityEventTokenVerifier;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;

/**
 * A1-6: the agent registry kept in the Contexa database, and the console's agent screens. It runs before the core
 * configuration so its registry replaces the in-memory default; without the Contexa database the in-memory registry
 * is used here as well. The control of what an agent learned (docs/agent A3-8) works when the autonomous security
 * plane runs; without it the console and the admin API refuse every action.
 */
@AutoConfiguration(before = CoreAutonomousAutoConfiguration.class)
public class IamAgentRegistryAutoConfiguration {

    @Bean(name = "contexaAgentRegistry")
    @ConditionalOnMissingBean(AgentRegistry.class)
    public AgentRegistry agentRegistry(@Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperations) {
        JdbcOperations operations = jdbcOperations.getIfAvailable();
        return operations != null ? new JdbcAgentRegistry(operations) : new InMemoryAgentRegistry();
    }

    /** docs/agent OC-1: the delegations kept in the Contexa database; without it the core keeps them in memory. */
    @Bean(name = "contexaDelegationRegistry")
    @ConditionalOnMissingBean(DelegationRegistry.class)
    public DelegationRegistry delegationRegistry(@Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperations,
                                                 ObjectProvider<SecurityZeroTrustProperties> properties) {
        JdbcOperations operations = jdbcOperations.getIfAvailable();
        Duration maxValidity = properties.getIfAvailable(SecurityZeroTrustProperties::new).getAgent()
                .getDelegationMaxValidity();
        return operations != null ? new JdbcDelegationRegistry(operations, maxValidity, null)
                : new InMemoryDelegationRegistry(maxValidity, null);
    }

    /** docs/agent A5-3, A5-2: the notices kept in the Contexa database when it is there, else in memory. */
    @Bean(name = "contexaAgentNoticeStore")
    @ConditionalOnMissingBean(AgentNoticeStore.class)
    public AgentNoticeStore agentNoticeStore(@Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperations) {
        JdbcOperations jdbc = jdbcOperations.getIfAvailable();
        return jdbc != null ? new JdbcAgentNoticeStore(jdbc) : new InMemoryAgentNoticeStore();
    }

    /** docs/agent A5-3, A5-2: notices delivered by the application's channel and kept for the console. */
    @Bean(name = "contexaAgentNotices")
    @ConditionalOnMissingBean
    public AgentNotices agentNotices(AgentNoticeStore contexaAgentNoticeStore, ObjectProvider<AgentNoticeChannel> channel) {
        return new AgentNotices(contexaAgentNoticeStore, channel.getIfAvailable());
    }

    /** docs/agent A5-4: the narrowed scopes of agents kept in the Contexa database, else in memory. */
    @Bean(name = "contexaAgentScopeStore")
    @ConditionalOnMissingBean(AgentScopeStore.class)
    public AgentScopeStore agentScopeStore(@Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperations) {
        JdbcOperations jdbc = jdbcOperations.getIfAvailable();
        return jdbc != null ? new JdbcAgentScopeStore(jdbc) : new InMemoryAgentScopeStore();
    }

    /**
     * docs/agent A5-2~A5-4: an account's deletion also removes the narrowed scopes of the agents that acted for the
     * person, the confirmations of their requests and the person's notices.
     */
    @Bean(name = "contexaAgentRequestStatePurgeContributor")
    @ConditionalOnMissingBean
    public AgentRequestStatePurgeContributor agentRequestStatePurgeContributor(AgentScopeStore contexaAgentScopeStore,
                                                                               AgentConfirmationStore contexaAgentConfirmationStore,
                                                                               AgentNoticeStore contexaAgentNoticeStore) {
        return new AgentRequestStatePurgeContributor(contexaAgentScopeStore, contexaAgentConfirmationStore, contexaAgentNoticeStore);
    }

    /** docs/agent A5-2: the confirmations of agents' requests kept in the Contexa database, else in memory. */
    @Bean(name = "contexaAgentConfirmationStore")
    @ConditionalOnMissingBean(AgentConfirmationStore.class)
    public AgentConfirmationStore agentConfirmationStore(
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperations) {
        JdbcOperations jdbc = jdbcOperations.getIfAvailable();
        return jdbc != null ? new JdbcAgentConfirmationStore(jdbc) : new InMemoryAgentConfirmationStore();
    }

    /**
     * docs/agent A5-2, A5-9, F-2: the confirmation of agents' requests by the people accountable for them. A report
     * stops the agent through the autonomous security plane's containment when it runs.
     */
    @Bean(name = "contexaAgentConfirmationService")
    @ConditionalOnMissingBean
    public AgentConfirmationService agentConfirmationService(AgentConfirmationStore contexaAgentConfirmationStore,
                                                             ObjectProvider<AgentConfirmationAuthorizer> authorizer,
                                                             AgentNotices contexaAgentNotices, AgentRegistry contexaAgentRegistry,
                                                             ObjectProvider<CentralAuditFacade> auditFacade,
                                                             ObjectProvider<SecurityZeroTrustProperties> properties,
                                                             ObjectProvider<EvidenceSigner> evidenceSigner,
                                                             ObjectProvider<AgentContainmentService> containment) {
        AgentConfirmationService service = new AgentConfirmationService(contexaAgentConfirmationStore,
                authorizer.getIfAvailable(() -> new SignedAgentConfirmationAuthorizer(
                        evidenceSigner.getIfAvailable(() -> HmacEvidenceSigner.of(Map.of(), null)))),
                contexaAgentNotices, contexaAgentRegistry, auditFacade.getIfAvailable(),
                properties.getIfAvailable(SecurityZeroTrustProperties::new).getAgent().getConfirmationTimeout(),
                null);
        service.setContainment(containment.getIfAvailable());
        return service;
    }

    /**
     * docs/agent A5-7: the call limits of agents and delegations and the denial alarm. Past a limit that stops, the
     * autonomous security plane's containment stops the agent when it runs.
     */
    @Bean(name = "contexaAgentCallGuard")
    @ConditionalOnMissingBean
    public AgentCallGuard agentCallGuard(ObjectProvider<SecurityZeroTrustProperties> properties,
                                         AgentNotices contexaAgentNotices, AgentRegistry contexaAgentRegistry,
                                         ObjectProvider<CentralAuditFacade> auditFacade,
                                         ObjectProvider<AgentContainmentService> containment) {
        SecurityZeroTrustProperties.AgentSettings agent = properties.getIfAvailable(SecurityZeroTrustProperties::new)
                .getAgent();
        AgentCallGuard guard = new AgentCallGuard(agent.getCallLimit(), agent.getDenialAlarm(), contexaAgentNotices,
                contexaAgentRegistry, auditFacade.getIfAvailable(), null);
        guard.setContainment(containment.getIfAvailable());
        // docs/agent G-9: in the report-only mode a passed limit is recorded, not acted on.
        SecurityZeroTrustProperties zeroTrust = properties.getIfAvailable(SecurityZeroTrustProperties::new);
        guard.setEnforcing(zeroTrust::isEnforcementEnabled);
        return guard;
    }

    /** docs/agent A5-2: the confirmations not decided or used in time are refused and recorded on schedule. */
    @Bean(name = "contexaAgentConfirmationExpiry")
    @ConditionalOnMissingBean
    public AgentConfirmationExpiry agentConfirmationExpiry(AgentConfirmationService contexaAgentConfirmationService) {
        return new AgentConfirmationExpiry(contexaAgentConfirmationService);
    }

    /** docs/agent OC-2: the company records kept in the Contexa database; without it the core keeps them in memory. */
    @Bean(name = "contexaCompanyRecordStore")
    @ConditionalOnMissingBean(CompanyRecordStore.class)
    public CompanyRecordStore companyRecordStore(
            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbcOperations) {
        JdbcOperations operations = jdbcOperations.getIfAvailable();
        return operations != null ? new JdbcCompanyRecordStore(operations) : new InMemoryCompanyRecordStore();
    }

    /** docs/agent OC-2: the admin API and the console of company records. */
    @Bean(name = "contexaCompanyRecordsAdminService")
    @ConditionalOnMissingBean
    public CompanyRecordsAdminService companyRecordsAdminService(CompanyRecordStore contexaCompanyRecordStore,
                                                                 ObjectProvider<CentralAuditFacade> auditFacade) {
        return new CompanyRecordsAdminService(contexaCompanyRecordStore, auditFacade.getIfAvailable());
    }

    @Bean(name = "contexaCompanyRecordsApiController")
    @ConditionalOnMissingBean
    public CompanyRecordsApiController companyRecordsApiController(CompanyRecordsAdminService contexaCompanyRecordsAdminService) {
        return new CompanyRecordsApiController(contexaCompanyRecordsAdminService);
    }

    @Bean(name = "contexaCompanyRecordsAdminController")
    @ConditionalOnMissingBean
    public CompanyRecordsAdminController companyRecordsAdminController(
            CompanyRecordsAdminService contexaCompanyRecordsAdminService) {
        return new CompanyRecordsAdminController(contexaCompanyRecordsAdminService);
    }

    @Bean(name = "contexaAgentLearningAdminService")
    @ConditionalOnMissingBean
    public AgentLearningAdminService agentLearningAdminService(ObjectProvider<AgentLearningControl> control,
                                                               ObjectProvider<CentralAuditFacade> auditFacade) {
        return new AgentLearningAdminService(control.getIfAvailable(), auditFacade.getIfAvailable());
    }

    /** docs/agent OC-1: records and revokes delegations for the APIs and the console, audited. */
    @Bean(name = "contexaAgentDelegationService")
    @ConditionalOnMissingBean
    public AgentDelegationService agentDelegationService(DelegationRegistry contexaDelegationRegistry,
                                                         ObjectProvider<AgentClientDirectory> agentClientDirectory,
                                                         ObjectProvider<CentralAuditFacade> auditFacade) {
        return new AgentDelegationService(contexaDelegationRegistry, agentClientDirectory.getIfAvailable(),
                auditFacade.getIfAvailable());
    }

    @Bean(name = "contexaAgentDelegationApiController")
    @ConditionalOnMissingBean
    public AgentDelegationApiController agentDelegationApiController(AgentDelegationService contexaAgentDelegationService) {
        return new AgentDelegationApiController(contexaAgentDelegationService);
    }

    @Bean(name = "contexaAgentDelegationAdminApiController")
    @ConditionalOnMissingBean
    public AgentDelegationAdminApiController agentDelegationAdminApiController(
            AgentDelegationService contexaAgentDelegationService) {
        return new AgentDelegationAdminApiController(contexaAgentDelegationService);
    }

    @Bean(name = "contexaAgentAdminController")
    @ConditionalOnMissingBean
    public AgentAdminController agentAdminController(AgentRegistry contexaAgentRegistry, MessageSource messageSource,
                                                     AgentLearningAdminService contexaAgentLearningAdminService,
                                                     AgentDelegationService contexaAgentDelegationService,
                                                     ObjectProvider<AgentProvisioning> agentProvisioning,
                                                     ObjectProvider<AuditLogRepository> auditLogRepository) {
        AgentAdminController controller = new AgentAdminController(contexaAgentRegistry, messageSource,
                contexaAgentLearningAdminService, contexaAgentDelegationService,
                agentProvisioning.getIfAvailable(AgentProvisioning::unavailable));
        // docs/agent A5-5: the agents' latest decisions, from the decision records.
        auditLogRepository.ifAvailable(controller::setDecisionRecords);
        return controller;
    }

    /** docs/agent OC-3: the admin API of agent registration. */
    @Bean(name = "contexaAgentRegistrationApiController")
    @ConditionalOnMissingBean
    public AgentRegistrationApiController agentRegistrationApiController(
            ObjectProvider<AgentProvisioning> agentProvisioning, AgentRegistry contexaAgentRegistry) {
        return new AgentRegistrationApiController(agentProvisioning.getIfAvailable(AgentProvisioning::unavailable),
                contexaAgentRegistry);
    }

    /**
     * docs/agent A5-8: the push endpoint of revocation and risk signals, on when
     * {@code contexa.security.zerotrust.risk-signals.receiver-enabled} is true: the configured transmitters' tokens
     * invalidate the decisions of the subjects they name.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "io.contexa.contexaidentity.security.signal.JwtSecurityEventTokenVerifier")
    @ConditionalOnProperty(prefix = "contexa.security.zerotrust.risk-signals", name = "receiver-enabled",
            havingValue = "true")
    static class RiskSignalReceiverConfiguration {

        @Bean(name = "contexaSecurityEventTokenVerifier")
        @ConditionalOnMissingBean(SecurityEventTokenVerifier.class)
        SecurityEventTokenVerifier securityEventTokenVerifier(ObjectProvider<SecurityZeroTrustProperties> properties) {
            SecurityZeroTrustProperties.RiskSignals settings = properties.getIfAvailable(SecurityZeroTrustProperties::new)
                    .getRiskSignals();
            Map<String, JwtDecoder> decoders = new LinkedHashMap<>();
            for (SecurityZeroTrustProperties.RiskSignals.Transmitter transmitter : settings.getTransmitters()) {
                if (transmitter.getIssuer() == null || transmitter.getJwksUri() == null) {
                    throw new IllegalStateException("A risk signal transmitter needs its issuer and its jwks-uri");
                }
                decoders.put(transmitter.getIssuer(), JwtSecurityEventTokenVerifier.jwksDecoder(transmitter.getJwksUri()));
            }
            return new JwtSecurityEventTokenVerifier(decoders, settings.getAudience());
        }

        @Bean(name = "contexaRiskSignalReceiver")
        @ConditionalOnMissingBean
        RiskSignalReceiver riskSignalReceiver(ZeroTrustActionRepository actionRepository,
                                              ObjectProvider<ZeroTrustSecurityService> zeroTrustSecurityService,
                                              ObjectProvider<UserRepository> userRepository,
                                              ObjectProvider<CentralAuditFacade> auditFacade,
                                              ObjectProvider<IForceLogoutService> forceLogoutService) {
            UserRepository users = userRepository.getIfAvailable();
            return new RiskSignalReceiver(actionRepository, zeroTrustSecurityService.getIfAvailable(),
                    subjectId -> RiskSignalReceiver.userOf(subjectId, email -> users == null ? null
                            : users.findFirstByEmailIgnoreCase(email).map(Users::getUsername).orElse(null)),
                    auditFacade.getIfAvailable(), forceLogoutService.getIfAvailable());
        }

        @Bean(name = "contexaRiskSignalReceiverController")
        @ConditionalOnMissingBean
        RiskSignalReceiverController riskSignalReceiverController(SecurityEventTokenVerifier verifier,
                                                                  RiskSignalReceiver receiver) {
            return new RiskSignalReceiverController(verifier, receiver);
        }
    }

    /**
     * docs/agent A5-3, A5-2: what Contexa's identity module adds to agent notices and stops: mail through the
     * application's mail sender, and the revocation of the tokens its authorization server issued.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = {"io.contexa.contexaidentity.security.agent.MailAgentNoticeChannel",
            "org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository"})
    static class AgentIdentityConfiguration {

        @Bean(name = "contexaAgentNoticeChannel")
        @ConditionalOnMissingBean(AgentNoticeChannel.class)
        AgentNoticeChannel agentNoticeChannel(ObjectProvider<EmailService> emailService,
                                              ObjectProvider<UserRepository> userRepository) {
            return new MailAgentNoticeChannel(emailService.getIfAvailable(), userRepository.getIfAvailable());
        }

        /**
         * docs/agent A5-2: an approval is recorded as an authorization of Contexa's authorization server when it runs
         * here and registers the agent's client; otherwise as a keyed signature.
         */
        @Bean(name = "contexaAgentConfirmationAuthorizer")
        @ConditionalOnMissingBean(AgentConfirmationAuthorizer.class)
        AgentConfirmationAuthorizer agentConfirmationAuthorizer(ObjectProvider<OAuth2AuthorizationService> authorizations,
                                                                ObjectProvider<RegisteredClientRepository> clients,
                                                                ObjectProvider<AgentRegistry> agentRegistry,
                                                                ObjectProvider<EvidenceSigner> evidenceSigner) {
            AgentConfirmationAuthorizer signed = new SignedAgentConfirmationAuthorizer(
                    evidenceSigner.getIfAvailable(() -> HmacEvidenceSigner.of(Map.of(), null)));
            OAuth2AuthorizationService service = authorizations.getIfAvailable();
            RegisteredClientRepository repository = clients.getIfAvailable();
            return service != null && repository != null
                    ? new OAuth2AgentConfirmationAuthorizer(service, repository, agentRegistry.getIfAvailable(), signed)
                    : signed;
        }

        @Bean(name = "contexaAgentTokenRevoker")
        @ConditionalOnMissingBean(AgentTokenRevoker.class)
        AgentTokenRevoker agentTokenRevoker(ObjectProvider<OAuth2AuthorizationService> authorizations,
                                            ObjectProvider<RegisteredClientRepository> clients) {
            RegisteredClientRepository repository = clients.getIfAvailable();
            if (authorizations.getIfAvailable() instanceof DeviceAwareOAuth2AuthorizationService service
                    && repository != null) {
                return new OAuth2AgentTokenRevoker(service, repository);
            }
            return AgentTokenRevoker.NONE;
        }
    }

    /**
     * docs/agent OC-3: agents are registered with Contexa's authorization server when it runs: their OAuth2 client,
     * their registry entry and, when asked, their account.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository")
    static class AgentProvisioningConfiguration {

        @Bean(name = "contexaAgentProvisioning")
        @ConditionalOnMissingBean(AgentProvisioning.class)
        AgentProvisioning agentProvisioning(AgentRegistry contexaAgentRegistry,
                                            ObjectProvider<RegisteredClientRepository> clients,
                                            BeanFactory beanFactory,
                                            @Qualifier("contexaJdbcTemplate") ObjectProvider<JdbcOperations> jdbc,
                                            ObjectProvider<UserManagementService> users,
                                            ObjectProvider<UserRepository> userRepository,
                                            ObjectProvider<GroupRepository> groups,
                                            ObjectProvider<CentralAuditFacade> auditFacade,
                                            ObjectProvider<SecurityZeroTrustProperties> properties,
                                            ObjectProvider<UserEngineStatePurger> engineStatePurger) {
            RegisteredClientRepository repository = clients.getIfAvailable();
            PasswordEncoder encoder = ContexaOwnBeans.passwordEncoder(beanFactory);
            if (repository == null) {
                return AgentProvisioning.unavailable();
            }
            OAuth2AgentProvisioning provisioning = new OAuth2AgentProvisioning(contexaAgentRegistry, repository, encoder,
                    jdbc.getIfAvailable(), users.getIfAvailable(), userRepository.getIfAvailable(),
                    groups.getIfAvailable(), auditFacade.getIfAvailable(),
                    properties.getIfAvailable(SecurityZeroTrustProperties::new).getAgent().getClientTokenLifetime());
            provisioning.setEngineStatePurger(engineStatePurger.getIfAvailable());
            return provisioning;
        }
    }

    @Bean(name = "contexaAgentLearningApiController")
    @ConditionalOnMissingBean
    public AgentLearningApiController agentLearningApiController(AgentLearningAdminService contexaAgentLearningAdminService) {
        return new AgentLearningApiController(contexaAgentLearningAdminService);
    }

    /**
     * docs/agent A5-3 (AM-4): the console's agent stops. Acting on them needs the autonomous security plane's
     * containment; without it the stops are shown and every action is refused.
     */
    @Bean(name = "contexaAgentContainmentAdminService")
    @ConditionalOnMissingBean
    public AgentContainmentAdminService agentContainmentAdminService(
            ObjectProvider<AgentContainmentService> containment, AgentRegistry contexaAgentRegistry,
            ObjectProvider<AuditLogRepository> auditLogRepository, AgentNoticeStore contexaAgentNoticeStore,
            ObjectProvider<AgentScopeService> scopes) {
        AgentContainmentAdminService service = new AgentContainmentAdminService(containment.getIfAvailable(),
                contexaAgentRegistry, auditLogRepository.getIfAvailable(), contexaAgentNoticeStore);
        // docs/agent A5-4: the agents still narrowed, shown with the stops.
        service.setScopes(scopes.getIfAvailable());
        return service;
    }

    @Bean(name = "contexaAgentStopController")
    @ConditionalOnMissingBean
    public AgentStopController agentStopController(AgentContainmentAdminService contexaAgentContainmentAdminService,
                                                   MessageSource messageSource) {
        return new AgentStopController(contexaAgentContainmentAdminService, messageSource);
    }

    @Bean(name = "contexaAgentStopApiController")
    @ConditionalOnMissingBean
    public AgentStopApiController agentStopApiController(AgentContainmentAdminService contexaAgentContainmentAdminService) {
        return new AgentStopApiController(contexaAgentContainmentAdminService);
    }

    /**
     * docs/agent A5-2 (AC-1~AC-3): the pages a person confirms an agent's request on, and where the agent follows its
     * confirmation. They need the confirmation of the autonomous security plane.
     */
    @Bean(name = "contexaAgentConfirmationController")
    @ConditionalOnMissingBean
    public AgentConfirmationController agentConfirmationController(AgentConfirmationService contexaAgentConfirmationService,
                                                                   MessageSource messageSource,
                                                                   ObjectProvider<DelegationRegistry> delegations,
                                                                   ObjectProvider<AuditLogRepository> auditLogRepository,
                                                                   AgentNoticeStore contexaAgentNoticeStore,
                                                                   ObjectProvider<AgentContainmentAdminService> stops) {
        AgentConfirmationController controller = new AgentConfirmationController(contexaAgentConfirmationService,
                messageSource);
        controller.setDelegations(delegations.getIfAvailable());
        controller.setDecisionRecords(auditLogRepository.getIfAvailable());
        controller.setNotices(contexaAgentNoticeStore);
        // docs/agent A5-3: the accountable person releases their own stopped agent too.
        controller.setStops(stops.getIfAvailable());
        return controller;
    }

    @Bean(name = "contexaAgentConfirmationApiController")
    @ConditionalOnMissingBean
    public AgentConfirmationApiController agentConfirmationApiController(
            AgentConfirmationService contexaAgentConfirmationService, ObjectProvider<AgentCallGuard> agentCallGuard,
            ObjectProvider<SecurityZeroTrustProperties> properties) {
        AgentConfirmationApiController controller = new AgentConfirmationApiController(contexaAgentConfirmationService);
        // docs/agent A5-7: an agent's asks count against its call limits, as its other calls do at the gate.
        controller.setCallGuard(agentCallGuard.getIfAvailable());
        // docs/agent A5-2: the mail of an agent's own ask links where the gate's mails link.
        controller.setLinkBaseUrl(properties.getIfAvailable(SecurityZeroTrustProperties::new).getAgent()
                .getConfirmationLinkBaseUrl());
        return controller;
    }
}
