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
package io.contexa.autoconfigure.core.infra;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.infra.kafka.KafkaConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.kafka.KafkaAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * An application that has Kafka of its own (Spring Boot's auto-configuration, its own serializers) keeps its template and its producer
 * factory when Contexa runs in the distributed mode: Contexa's Kafka beans are for Contexa's code and are asked for by name.
 */
class ContexaKafkaHostCoexistenceTest {

    @Configuration(proxyBeanMethods = false)
    static class ContexaSide {
        @Bean(name = "contexaObjectMapper", defaultCandidate = false)
        ObjectMapper contexaObjectMapper() {
            return new ObjectMapper();
        }
    }

    private ApplicationContextRunner runner() {
        return new ApplicationContextRunner()
                .withPropertyValues("contexa.infrastructure.mode=distributed", "spring.kafka.bootstrap-servers=127.0.0.1:1",
                        "spring.kafka.producer.value-serializer=org.apache.kafka.common.serialization.StringSerializer")
                .withUserConfiguration(ContexaSide.class, KafkaConfiguration.class)
                .withConfiguration(AutoConfigurations.of(KafkaAutoConfiguration.class));
    }

    @Test
    void theContextStarts() {
        runner().run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void theApplicationsOwnTemplateIsMadeFromTheApplicationsOwnProducerFactory() {
        runner().run(context -> {
            assertThat(context).hasNotFailed();
            KafkaTemplate<?, ?> hosts = context.getBean("kafkaTemplate", KafkaTemplate.class);
            ProducerFactory<?, ?> contexas = context.getBean("contexaProducerFactory", ProducerFactory.class);

            assertThat(hosts.getProducerFactory()).as("the application's template does not send through Contexa's JSON producer factory")
                    .isNotSameAs(contexas);
        });
    }

    @Test
    void theApplicationsOwnProducerFactoryStillExists() {
        runner().run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).as("Spring Boot's producer factory is not pushed aside by Contexa's").hasBean("kafkaProducerFactory");
        });
    }
}
