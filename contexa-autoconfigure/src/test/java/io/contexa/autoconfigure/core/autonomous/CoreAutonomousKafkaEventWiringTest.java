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
import io.contexa.contexacore.autonomous.event.listener.KafkaSecurityEventCollector;
import io.contexa.contexacore.autonomous.event.publisher.KafkaSecurityEventPublisher;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * In the distributed mode Contexa's Kafka collector and publisher exist because of Contexa's own template, which is not offered to the
 * application's code, whether or not the application has a template of its own.
 */
class CoreAutonomousKafkaEventWiringTest {

    @Configuration(proxyBeanMethods = false)
    static class ContexasOwnTemplate {

        @Bean(name = "contexaObjectMapper", defaultCandidate = false)
        ObjectMapper contexaObjectMapper() {
            return new ObjectMapper();
        }

        @Bean(name = "contexaKafkaTemplate", defaultCandidate = false)
        @SuppressWarnings("unchecked")
        KafkaTemplate<String, Object> contexaKafkaTemplate() {
            return new KafkaTemplate<>(mock(ProducerFactory.class));
        }

        @Bean
        SecurityKafkaProperties securityKafkaProperties() {
            return new SecurityKafkaProperties();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class ApplicationsOwnTemplate {

        @Bean
        @SuppressWarnings("unchecked")
        KafkaTemplate<String, Object> kafkaTemplate() {
            return new KafkaTemplate<>(mock(ProducerFactory.class));
        }
    }

    private ApplicationContextRunner runner() {
        return new ApplicationContextRunner()
                .withPropertyValues("contexa.infrastructure.mode=distributed")
                .withUserConfiguration(ContexasOwnTemplate.class)
                .withConfiguration(AutoConfigurations.of(CoreAutonomousEventAutoConfiguration.KafkaEventConfiguration.class));
    }

    @Test
    void theCollectorAndThePublisherAreMadeFromContexasOwnTemplate() {
        runner().run(context -> {
            assertThat(context).hasNotFailed();

            assertThat(context).hasSingleBean(KafkaSecurityEventCollector.class).hasSingleBean(KafkaSecurityEventPublisher.class);
        });
    }

    @Test
    void anApplicationWithATemplateOfItsOwnDoesNotChangeThat() {
        runner().withUserConfiguration(ApplicationsOwnTemplate.class).run(context -> {
            assertThat(context).hasNotFailed();

            assertThat(context).hasSingleBean(KafkaSecurityEventCollector.class).hasSingleBean(KafkaSecurityEventPublisher.class);
        });
    }

    @Test
    void nothingIsMadeOutsideTheDistributedMode() {
        new ApplicationContextRunner()
                .withUserConfiguration(ContexasOwnTemplate.class)
                .withConfiguration(AutoConfigurations.of(CoreAutonomousEventAutoConfiguration.KafkaEventConfiguration.class))
                .run(context -> assertThat(context).doesNotHaveBean(KafkaSecurityEventCollector.class)
                        .doesNotHaveBean(KafkaSecurityEventPublisher.class));
    }
}
