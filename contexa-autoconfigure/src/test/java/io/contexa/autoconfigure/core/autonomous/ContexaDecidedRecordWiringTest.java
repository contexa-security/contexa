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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.event.listener.DecidedRecordAcknowledger;
import io.contexa.contexacore.autonomous.event.listener.KafkaSecurityEventCollector;
import io.contexa.contexacore.infra.kafka.KafkaConfiguration;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.kafka.KafkaAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.config.KafkaListenerEndpointRegistry;
import org.springframework.kafka.listener.ContainerProperties;
import org.springframework.kafka.listener.MessageListenerContainer;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/** The container and the collector share what keeps the commit below the undecided records, and existing settings bound it. */
class ContexaDecidedRecordWiringTest {

    @Configuration(proxyBeanMethods = false)
    static class ContexaSide {
        @Bean(name = "contexaObjectMapper", defaultCandidate = false)
        ObjectMapper contexaObjectMapper() {
            return new ObjectMapper();
        }

        @Bean
        SecurityKafkaProperties securityKafkaProperties() {
            return new SecurityKafkaProperties();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(SecurityPlaneProperties.class)
    static class PlaneSettings {
    }

    private ApplicationContextRunner runner() {
        return new ApplicationContextRunner()
                .withPropertyValues("contexa.infrastructure.mode=distributed", "spring.kafka.bootstrap-servers=127.0.0.1:1",
                        "spring.kafka.listener.auto-startup=false")
                .withUserConfiguration(ContexaSide.class, KafkaConfiguration.class)
                .withConfiguration(AutoConfigurations.of(KafkaAutoConfiguration.class,
                        CoreAutonomousEventAutoConfiguration.KafkaEventConfiguration.class));
    }

    @Test
    void theContainerTellsWhatItLosesToWhatTheCollectorHolds() {
        runner().run(context -> {
            assertThat(context).hasNotFailed();
            DecidedRecordAcknowledger acknowledger =
                    context.getBean("contexaDecidedRecordAcknowledger", DecidedRecordAcknowledger.class);
            ConcurrentKafkaListenerContainerFactory<?, ?> factory =
                    context.getBean("contexaKafkaListenerContainerFactory", ConcurrentKafkaListenerContainerFactory.class);

            assertThat(factory.getContainerProperties().getConsumerRebalanceListener()).isSameAs(acknowledger);
            assertThat(ReflectionTestUtils.getField(context.getBean(KafkaSecurityEventCollector.class), "decidedRecords"))
                    .isSameAs(acknowledger);
        });
    }

    /** What the factory is given has to reach the container of the listener, which is the one that loses partitions. */
    @Test
    void theContainerOfTheListenerIsTheOneThatTells() {
        runner().run(context -> {
            MessageListenerContainer container = context.getBean(KafkaListenerEndpointRegistry.class)
                    .getListenerContainers().iterator().next();

            assertThat(container.getContainerProperties().getConsumerRebalanceListener()).isSameAs(
                    context.getBean("contexaDecidedRecordAcknowledger", DecidedRecordAcknowledger.class));
        });
    }

    /** The consumer is never paused: {@code asyncAcks} would hold every partition behind one decision. */
    @Test
    void theContainerDoesNotPauseForAcknowledgments() {
        runner().run(context -> {
            ContainerProperties properties = context.getBean("contexaKafkaListenerContainerFactory",
                    ConcurrentKafkaListenerContainerFactory.class).getContainerProperties();

            assertThat(properties.getAckMode()).isEqualTo(ContainerProperties.AckMode.MANUAL_IMMEDIATE);
            assertThat(properties.isAsyncAcks()).isFalse();
        });
    }

    @Test
    void aRecordHoldsTheCommitForAsLongAsTheAnalysisOfOneRequestMayTake() {
        runner().run(context -> assertThat(limit(context.getBean("contexaDecidedRecordAcknowledger",
                DecidedRecordAcknowledger.class))).isEqualTo(Duration.ofMinutes(13)));
    }

    @Test
    void theLimitFollowsTheSettingsOfTheAnalysis() {
        runner().withUserConfiguration(PlaneSettings.class)
                .withPropertyValues("contexa.security.plane.agent.event-timeout-ms=10000",
                        "contexa.security.plane.agent.max-deferred-retries=1",
                        "contexa.security.plane.agent.deleted-account-fence-margin-ms=5000")
                .run(context -> assertThat(limit(context.getBean("contexaDecidedRecordAcknowledger",
                        DecidedRecordAcknowledger.class))).isEqualTo(Duration.ofSeconds(25)));
    }

    /** The standalone mode has no broker: nothing is held, and nothing but the collector in memory is there. */
    @Test
    void theStandaloneModeHasNoneOfIt() {
        new ApplicationContextRunner()
                .withUserConfiguration(ContexaSide.class, KafkaConfiguration.class)
                .withConfiguration(AutoConfigurations.of(CoreAutonomousEventAutoConfiguration.KafkaEventConfiguration.class))
                .run(context -> assertThat(context).doesNotHaveBean("contexaDecidedRecordAcknowledger")
                        .doesNotHaveBean(KafkaSecurityEventCollector.class));
    }

    private static Object limit(DecidedRecordAcknowledger acknowledger) {
        return ReflectionTestUtils.getField(acknowledger, "decisionLimit");
    }
}
