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

import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import io.contexa.contexacommon.security.bridge.runtime.RequestPathDatabaseGuard;
import io.contexa.autoconfigure.ai.AiBridgeConfiguration;
import io.contexa.autoconfigure.core.autonomous.CoreAutonomousAutoConfiguration;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.resolver.DelegationStampResolver;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.subject.AgentClientDirectory;
import io.contexa.contexacore.autonomous.agent.ActiveAgentList;
import io.contexa.contexacore.autonomous.agent.AgentLearningControl;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import io.contexa.contexacore.autonomous.agent.InMemoryDelegationRegistry;
import io.contexa.contexacore.autonomous.agent.AgentRegistrationRequest;
import io.contexa.contexacore.autonomous.agent.AgentRegistry;
import io.contexa.contexacore.autonomous.agent.AgentRegistryRecorder;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentRegistry;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.company.CompanyRecordStore;
import io.contexa.contexacore.autonomous.company.InMemoryCompanyRecordStore;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.web.agent.controller.AgentAdminController;
import io.contexa.contexaiam.admin.web.agent.controller.AgentDelegationAdminApiController;
import io.contexa.contexaiam.admin.web.agent.controller.AgentDelegationApiController;
import io.contexa.contexaiam.admin.web.agent.controller.AgentLearningApiController;
import io.contexa.contexaiam.admin.web.agent.controller.AgentRegistrationApiController;
import io.contexa.contexaiam.admin.web.agent.service.AgentProvisioning;
import io.contexa.contexaiam.admin.web.agent.service.AgentDelegationService;
import io.contexa.contexaiam.admin.web.agent.service.AgentLearningAdminService;
import io.contexa.contexaiam.admin.web.company.controller.CompanyRecordsAdminController;
import io.contexa.contexaiam.admin.web.company.controller.CompanyRecordsApiController;
import io.contexa.contexaiam.admin.web.company.service.CompanyRecordsAdminService;
import io.contexa.contexaiam.agent.JdbcAgentRegistry;
import io.contexa.contexaiam.agent.JdbcAgentConfirmationStore;
import io.contexa.contexaiam.agent.web.AgentConfirmationApiController;
import io.contexa.contexaiam.agent.web.AgentConfirmationController;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationAuthorizer;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationExpiry;
import io.contexa.contexacore.autonomous.agent.AgentCallGuard;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationService;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationStore;
import io.contexa.contexacore.autonomous.agent.AgentNotices;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentConfirmationStore;
import io.contexa.contexacore.autonomous.agent.InMemoryAgentNoticeStore;
import io.contexa.contexacore.verification.evidence.EvidenceSigner;
import io.contexa.contexacore.verification.evidence.HmacEvidenceSigner;
import io.contexa.contexaiam.agent.JdbcCompanyRecordStore;
import io.contexa.contexaiam.agent.JdbcDelegationRegistry;
import io.contexa.contexacommon.repository.AuditLogRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.support.StaticMessageSource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.function.Supplier;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** A1-6: the registry is the database one when the Contexa database is there, and every agent request reaches it. */
class AgentRegistryWiringTest {

    @Test
    @SuppressWarnings("unchecked")
    void theRegistryIsKeptInTheContexaDatabaseWhenItIsThere() {
        ObjectProvider<JdbcOperations> withDatabase = mock(ObjectProvider.class);
        when(withDatabase.getIfAvailable()).thenReturn(mock(JdbcOperations.class));
        ObjectProvider<JdbcOperations> withoutDatabase = mock(ObjectProvider.class);

        IamAgentRegistryAutoConfiguration configuration = new IamAgentRegistryAutoConfiguration();

        assertThat(configuration.agentRegistry(withDatabase)).isInstanceOf(JdbcAgentRegistry.class);
        assertThat(configuration.agentRegistry(withoutDatabase)).isInstanceOf(InMemoryAgentRegistry.class);
        ObjectProvider<AgentLearningControl> noControl = mock(ObjectProvider.class);
        ObjectProvider<CentralAuditFacade> noAudit = mock(ObjectProvider.class);
        AgentLearningAdminService learning = configuration.agentLearningAdminService(noControl, noAudit);
        assertThat(learning.available()).isFalse();
        // docs/agent OC-1: the delegations kept in the Contexa database when it is there, else in memory.
        ObjectProvider<SecurityZeroTrustProperties> properties = mock(ObjectProvider.class);
        when(properties.getIfAvailable(any())).thenReturn(new SecurityZeroTrustProperties());
        assertThat(configuration.delegationRegistry(withDatabase, properties)).isInstanceOf(JdbcDelegationRegistry.class);
        DelegationRegistry inMemory = configuration.delegationRegistry(withoutDatabase, properties);
        assertThat(inMemory).isInstanceOf(InMemoryDelegationRegistry.class);
        ObjectProvider<AgentClientDirectory> noDirectory = mock(ObjectProvider.class);
        AgentDelegationService delegations = configuration.agentDelegationService(inMemory, noDirectory, noAudit);
        assertThat(configuration.agentDelegationApiController(delegations))
                .isInstanceOf(AgentDelegationApiController.class);
        assertThat(configuration.agentDelegationAdminApiController(delegations))
                .isInstanceOf(AgentDelegationAdminApiController.class);
        ObjectProvider<AgentProvisioning> noProvisioning = mock(ObjectProvider.class);
        when(noProvisioning.getIfAvailable(any())).thenReturn(AgentProvisioning.unavailable());
        // docs/agent A5-5: without an audit store the agent screens show no decisions.
        ObjectProvider<AuditLogRepository> noAuditLog = mock(ObjectProvider.class);
        assertThat(configuration.agentAdminController(new InMemoryAgentRegistry(), new StaticMessageSource(), learning,
                delegations, noProvisioning, noAuditLog)).isInstanceOf(AgentAdminController.class);
        // docs/agent OC-3: the admin API of agent registration answers without the authorization server too.
        assertThat(configuration.agentRegistrationApiController(noProvisioning, new InMemoryAgentRegistry()))
                .isInstanceOf(AgentRegistrationApiController.class);
        // docs/agent A3-8: the admin API of what an agent learned.
        assertThat(configuration.agentLearningApiController(learning)).isInstanceOf(AgentLearningApiController.class);
        // docs/agent OC-2: the company records kept in the Contexa database when it is there, else in memory.
        assertThat(configuration.companyRecordStore(withDatabase)).isInstanceOf(JdbcCompanyRecordStore.class);
        CompanyRecordStore records = configuration.companyRecordStore(withoutDatabase);
        assertThat(records).isInstanceOf(InMemoryCompanyRecordStore.class);
        CompanyRecordsAdminService companyRecords = configuration.companyRecordsAdminService(records, noAudit);
        assertThat(configuration.companyRecordsApiController(companyRecords))
                .isInstanceOf(CompanyRecordsApiController.class);
        assertThat(configuration.companyRecordsAdminController(companyRecords))
                .isInstanceOf(CompanyRecordsAdminController.class);
    }

    /** docs/agent A5-2: the confirmations, kept in the Contexa database when it is there, and their pages and API. */
    @Test
    @SuppressWarnings("unchecked")
    void theConfirmationsAreKeptInTheContexaDatabaseWhenItIsThereAndWorkWithoutTheSecurityPlane() {
        ObjectProvider<JdbcOperations> withDatabase = mock(ObjectProvider.class);
        when(withDatabase.getIfAvailable()).thenReturn(mock(JdbcOperations.class));
        IamAgentRegistryAutoConfiguration configuration = new IamAgentRegistryAutoConfiguration();

        assertThat(configuration.agentConfirmationStore(withDatabase)).isInstanceOf(JdbcAgentConfirmationStore.class);
        AgentConfirmationStore inMemory = configuration.agentConfirmationStore(mock(ObjectProvider.class));
        assertThat(inMemory).isInstanceOf(InMemoryAgentConfirmationStore.class);
        ObjectProvider<SecurityZeroTrustProperties> properties = mock(ObjectProvider.class);
        SecurityZeroTrustProperties settings = new SecurityZeroTrustProperties();
        settings.getAgent().setConfirmationTimeout(Duration.ofMinutes(5));
        settings.getAgent().setConfirmationLinkBaseUrl("https://app.test");
        when(properties.getIfAvailable(any())).thenReturn(settings);
        ObjectProvider<AgentConfirmationAuthorizer> noAuthorizer = mock(ObjectProvider.class);
        when(noAuthorizer.getIfAvailable(any())).thenAnswer(invocation ->
                ((Supplier<?>) invocation.getArgument(0)).get());
        ObjectProvider<EvidenceSigner> noSigner = mock(ObjectProvider.class);
        when(noSigner.getIfAvailable(any())).thenReturn(HmacEvidenceSigner.of(Map.of(), null));
        // Without the autonomous security plane there is no containment; the confirmations still work.
        AgentConfirmationService service = configuration.agentConfirmationService(inMemory, noAuthorizer,
                new AgentNotices(new InMemoryAgentNoticeStore(), null), new InMemoryAgentRegistry(),
                mock(ObjectProvider.class), properties, noSigner, mock(ObjectProvider.class));

        assertThat(service.timeout()).isEqualTo(Duration.ofMinutes(5));
        assertThat(configuration.agentConfirmationExpiry(service)).isInstanceOf(AgentConfirmationExpiry.class);
        assertThat(configuration.agentConfirmationController(service, new StaticMessageSource(),
                mock(ObjectProvider.class), mock(ObjectProvider.class), new InMemoryAgentNoticeStore(),
                mock(ObjectProvider.class)))
                .isInstanceOf(AgentConfirmationController.class);
        ObjectProvider<AgentCallGuard> callGuards = mock(ObjectProvider.class);
        AgentCallGuard callGuard = new AgentCallGuard(null, null, null, null, null, null);
        when(callGuards.getIfAvailable()).thenReturn(callGuard);
        // An agent's asks count against its call limits, which is why the API holds the guard of the gate.
        AgentConfirmationApiController api = configuration.agentConfirmationApiController(service, callGuards,
                properties);
        assertThat(ReflectionTestUtils.getField(api, "callGuard")).isSameAs(callGuard);
        // An agent's own ask is mailed with the address the gate's links start at.
        assertThat(ReflectionTestUtils.getField(api, "linkBaseUrl")).isEqualTo("https://app.test");
    }

    @Test
    void theDatabaseRegistryComesBeforeTheCoreDefault() throws Exception {
        assertThat(IamAgentRegistryAutoConfiguration.class.getAnnotation(AutoConfiguration.class).before())
                .containsExactly(CoreAutonomousAutoConfiguration.class);
        assertThat(CoreAutonomousAutoConfiguration.class.getDeclaredMethod("defaultAgentRegistry")
                .getAnnotation(ConditionalOnMissingBean.class).value()).containsExactly(AgentRegistry.class);
        assertThat(CoreAutonomousAutoConfiguration.class.getDeclaredMethod("defaultCompanyRecordStore")
                .getAnnotation(ConditionalOnMissingBean.class).value()).containsExactly(CompanyRecordStore.class);
        assertThat(new ClassPathResource("META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports")
                .getContentAsString(StandardCharsets.UTF_8))
                .contains("io.contexa.autoconfigure.iam.admin.IamAgentRegistryAutoConfiguration");
    }

    @Test
    void theRecorderTakesTheConfiguredWriteInterval() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.getAgent().setRegistryWriteInterval(Duration.ofSeconds(30));

        AgentRegistryRecorder recorder = new CoreAutonomousAutoConfiguration()
                .agentRegistryRecorder(new InMemoryAgentRegistry(), properties);

        assertThat(recorder).isNotNull();
        assertThat(properties.getAgent().getRegistryWriteInterval()).isEqualTo(Duration.ofSeconds(30));
    }

    @Test
    @SuppressWarnings("unchecked")
    void theRegistrysApprovedAgentsReachTheTokenDelegationStamp() {
        InMemoryAgentRegistry registry = new InMemoryAgentRegistry();
        registry.register(new AgentRegistrationRequest(null, "report-bot", "Report bot", null, "report-client", "carol", null));
        AgentClientDirectory directory = new CoreAutonomousAutoConfiguration().agentClientDirectory(registry, new DefaultListableBeanFactory().getBeanProvider(RequestPathDatabaseGuard.class), new DefaultListableBeanFactory().getBeanProvider(ActiveAgentList.class));
        ObjectProvider<AgentClientDirectory> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable(any())).thenReturn(directory);
        DelegationStampResolver resolver = new AiBridgeConfiguration().tokenDelegationStampResolver(provider);
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "RS256")
                .claim("sub", "report-client").claim("client_id", "report-client").build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt, List.of()));
        try {
            DelegationStamp stamp = resolver.resolve(null, null, new BridgeProperties()).orElseThrow();

            assertThat(stamp.agentId()).isEqualTo("report-bot");
            assertThat(stamp.delegated()).isFalse();
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void anApprovedAgentsSessionLoginIsReadAsThatAgent() {
        InMemoryAgentRegistry registry = new InMemoryAgentRegistry();
        registry.register(new AgentRegistrationRequest(null, "report-bot", "Report bot", null, "report-client", "carol", null));
        AgentClientDirectory directory = new CoreAutonomousAutoConfiguration().agentClientDirectory(registry, new DefaultListableBeanFactory().getBeanProvider(RequestPathDatabaseGuard.class), new DefaultListableBeanFactory().getBeanProvider(ActiveAgentList.class));
        ObjectProvider<AgentClientDirectory> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable(any())).thenReturn(directory);
        DelegationStampResolver resolver = new AiBridgeConfiguration().agentAccountDelegationStampResolver(provider);
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated("report-bot", null, List.of()));
        try {
            DelegationStamp stamp = resolver.resolve(null, null, new BridgeProperties()).orElseThrow();

            assertThat(stamp.agentId()).isEqualTo("report-bot");
            assertThat(stamp.delegated()).isFalse();
            SecurityContextHolder.getContext().setAuthentication(
                    UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of()));
            assertThat(resolver.resolve(null, null, new BridgeProperties())).isEmpty();
        } finally {
            SecurityContextHolder.clearContext();
        }
    }
}
