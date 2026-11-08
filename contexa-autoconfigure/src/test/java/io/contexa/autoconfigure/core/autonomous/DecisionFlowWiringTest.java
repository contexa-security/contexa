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
package io.contexa.autoconfigure.core.autonomous;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.SecurityEventProcessor;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.event.listener.KafkaSecurityEventCollector;
import io.contexa.contexacore.autonomous.event.listener.ZeroTrustEventListener;
import io.contexa.contexacore.autonomous.event.publisher.KafkaSecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.service.NewContextDecisionLimit;
import io.contexa.contexacore.autonomous.service.QueuedAgentEventRecheck;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import io.contexa.contexacore.properties.ModelServerGateProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.std.llm.gate.ModelServer;
import io.contexa.contexacore.std.llm.gate.ModelServerGates;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/** The settings and collaborators of the decision flow reach it through the auto-configuration, not through tests alone. */
class DecisionFlowWiringTest {

    @SuppressWarnings("unchecked")
    private static <T> ObjectProvider<T> none() {
        return mock(ObjectProvider.class);
    }

    private static <T> ObjectProvider<T> one(Class<T> type, T bean) {
        DefaultListableBeanFactory factory = new DefaultListableBeanFactory();
        factory.registerSingleton("bean", bean);
        return factory.getBeanProvider(type);
    }

    private static SynchronousProtectableDecisionService service(SecurityZeroTrustProperties properties) {
        return new CoreAutonomousAutoConfiguration().synchronousProtectableDecisionService(
                mock(ZeroTrustEventPublisher.class), mock(ZeroTrustEventListener.class), mock(SecurityPlaneAgent.class),
                mock(ZeroTrustActionRepository.class), none(), properties, none(), none(), none());
    }

    /** Calls from a changed context take from one window of the person's decisions, whose size is the setting's. */
    @Test
    void callsFromAChangedContextTakeFromTheConfiguredLimit() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.getAnalysis().getNewContextLimit().setDecisions(4);
        NewContextDecisionLimit limit = new CoreAutonomousEventAutoConfiguration().newContextDecisionLimit(properties,
                none());
        SynchronousProtectableDecisionService service = new CoreAutonomousAutoConfiguration()
                .synchronousProtectableDecisionService(mock(ZeroTrustEventPublisher.class), mock(ZeroTrustEventListener.class),
                        mock(SecurityPlaneAgent.class), mock(ZeroTrustActionRepository.class), none(), properties, none(),
                        none(), one(NewContextDecisionLimit.class, limit));

        assertThat(ReflectionTestUtils.getField(service, "newContextDecisionLimit")).isSameAs(limit);
        for (int i = 0; i < 4; i++) {
            assertThat(limit.take("alice", NewContextDecisionLimit.Kind.CHANGED_CONTEXT)).isTrue();
        }
        assertThat(limit.take("alice", NewContextDecisionLimit.Kind.CHANGED_CONTEXT)).as("the setting is read").isFalse();
    }

    @Test
    void aSynchronousRequestWaitsAsLongAsTheFlightsSay() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.getAgent().getFlight().setWait(Duration.ofSeconds(25));

        assertThat(ReflectionTestUtils.getField(service(properties), "decisionWait")).isEqualTo(Duration.ofSeconds(25));
    }

    @Test
    void nothingIsHeldWhereDecisionsAreNotEnforced() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.setMode(SecurityZeroTrustProperties.EnforcementMode.SHADOW);

        BooleanSupplier enforcing = (BooleanSupplier) ReflectionTestUtils.getField(service(properties), "enforcing");

        assertThat(enforcing.getAsBoolean()).isFalse();
    }

    @Test
    void whatKafkaDoesNotTakeReachesTheCollectorOfThisNode() {
        KafkaSecurityEventCollector collector = mock(KafkaSecurityEventCollector.class);

        KafkaSecurityEventPublisher publisher = new CoreAutonomousEventAutoConfiguration.KafkaEventConfiguration()
                .kafkaSecurityEventPublisher(template(), new SecurityKafkaProperties(),
                        one(KafkaSecurityEventCollector.class, collector));

        Object analysis = ReflectionTestUtils.getField(publisher, "localAnalysis");
        assertThat(analysis).isInstanceOf(Consumer.class);
        publisher.destroy();
    }

    @SuppressWarnings("unchecked")
    private static KafkaTemplate<String, Object> template() {
        return mock(KafkaTemplate.class);
    }

    @Test
    void aRequestLeftOutReachesTheRecheckOfTheAgent() {
        QueuedAgentEventRecheck recheck = mock(QueuedAgentEventRecheck.class);
        SecurityEvent event = SecurityEvent.builder().eventId("event-1").build();
        SecurityPlaneAgent agent = new CoreAutonomousAutoConfiguration().securityPlaneAgent(
                mock(SecurityMonitoringService.class), mock(SecurityContextDataStore.class), mock(CentralAuditFacade.class),
                mock(SecurityEventProcessor.class), new SecurityPlaneProperties(), Runnable::run, none(),
                mock(ZeroTrustActionRepository.class), none(), one(QueuedAgentEventRecheck.class, recheck), none());

        SecurityPlaneAgent.QueuedEventRecheck wired = (SecurityPlaneAgent.QueuedEventRecheck)
                ReflectionTestUtils.getField(agent, "queuedEventRecheck");
        wired.leftOut(event);

        verify(recheck).leftOut(event);
    }

    private static SecurityPlaneAgent agentWith(ObjectProvider<ModelServerGates> gates) {
        SecurityPlaneAgent agent = new CoreAutonomousAutoConfiguration().securityPlaneAgent(
                mock(SecurityMonitoringService.class), mock(SecurityContextDataStore.class), mock(CentralAuditFacade.class),
                mock(SecurityEventProcessor.class), new SecurityPlaneProperties(), Runnable::run, none(),
                mock(ZeroTrustActionRepository.class), none(), none(), gates);
        agent.initialize();
        return agent;
    }

    /** The analyses that run at once follow the gates of the model servers: two for each slot until a chat call is measured. */
    @Test
    void theAnalysesFollowTheGatesOfTheModelServers() {
        ModelServerGates gates = new ModelServerGates((model, kind) -> ModelServer.of("ollama", "http://localhost:11434"),
                new ModelServerGateProperties(), 180_000L);

        SecurityPlaneAgent agent = agentWith(one(ModelServerGates.class, gates));

        assertThat(agent.analysisActors()).isEqualTo(2 * 2);
    }

    @Test
    void withoutGatesTheAnalysisStripesAreTheLimit() {
        SecurityPlaneAgent agent = agentWith(none());

        assertThat(agent.analysisActors()).isEqualTo(new SecurityPlaneProperties().getAgent().getAnalysisStripes());
    }
}
