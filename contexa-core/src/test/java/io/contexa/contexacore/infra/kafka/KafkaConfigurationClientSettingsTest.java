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
package io.contexa.contexacore.infra.kafka;

import io.contexa.contexacommon.store.ApplicationNamespace;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.config.SslConfigs;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.kafka.KafkaAutoConfiguration;
import org.springframework.boot.autoconfigure.kafka.SslBundleSslEngineFactory;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.support.serializer.JsonSerializer;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * PR-88: an application reaches its Kafka the way Spring Boot documents it, and Contexa's clients reach the same Kafka.
 * What describes the cluster and how to get in is the application's; what Contexa's delivery depends on stays Contexa's.
 */
class KafkaConfigurationClientSettingsTest {

    @Configuration(proxyBeanMethods = false)
    static class ContexaSide {
        @Bean(name = "contexaObjectMapper", defaultCandidate = false)
        ObjectMapper contexaObjectMapper() {
            return new ObjectMapper();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class Bundles {
        @Bean
        SslBundles sslBundles() {
            SslBundles bundles = mock(SslBundles.class);
            when(bundles.getBundle("kafka")).thenReturn(mock(SslBundle.class));
            return bundles;
        }
    }

    private ApplicationContextRunner runner(String... properties) {
        return new ApplicationContextRunner()
                .withPropertyValues("contexa.infrastructure.mode=distributed", "spring.kafka.bootstrap-servers=127.0.0.1:1")
                .withPropertyValues(properties)
                .withUserConfiguration(ContexaSide.class, KafkaConfiguration.class)
                .withConfiguration(AutoConfigurations.of(KafkaAutoConfiguration.class));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> consumer(ApplicationContext context) {
        return context.getBean("contexaConsumerConfigs", Map.class);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> producer(ApplicationContext context) {
        return context.getBean("contexaProducerConfigs", Map.class);
    }

    @Test
    @DisplayName("the login Spring Boot was given reaches the consumer and the producer")
    void theLoginReachesBothClients() {
        String jaas = "org.apache.kafka.common.security.plain.PlainLoginModule required username=\"u\" password=\"p\";";
        runner("spring.kafka.security.protocol=SASL_PLAINTEXT", "spring.kafka.properties.sasl.mechanism=PLAIN",
                "spring.kafka.properties.sasl.jaas.config=" + jaas).run(context -> {
                    assertThat(context).hasNotFailed();
                    for (Map<String, Object> client : List.of(consumer(context), producer(context))) {
                        assertThat(client).containsEntry(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, "SASL_PLAINTEXT")
                                .containsEntry(SaslConfigs.SASL_MECHANISM, "PLAIN")
                                .containsEntry(SaslConfigs.SASL_JAAS_CONFIG, jaas);
                    }
                });
    }

    @Test
    @DisplayName("spring.kafka.ssl reaches the consumer and the producer")
    void theTlsSettingsReachBothClients() {
        runner("spring.kafka.ssl.trust-store-type=PKCS12", "spring.kafka.ssl.trust-store-password=secret").run(context -> {
            assertThat(context).hasNotFailed();
            for (Map<String, Object> client : List.of(consumer(context), producer(context))) {
                assertThat(client).containsEntry(SslConfigs.SSL_TRUSTSTORE_TYPE_CONFIG, "PKCS12")
                        .containsEntry(SslConfigs.SSL_TRUSTSTORE_PASSWORD_CONFIG, "secret");
            }
        });
    }

    @Test
    @DisplayName("an SSL bundle named under spring.kafka.ssl is resolved for both clients")
    void anSslBundleReachesBothClients() {
        runner("spring.kafka.ssl.bundle=kafka").withUserConfiguration(Bundles.class).run(context -> {
            assertThat(context).hasNotFailed();
            for (Map<String, Object> client : List.of(consumer(context), producer(context))) {
                assertThat(client).containsEntry(SslConfigs.SSL_ENGINE_FACTORY_CLASS_CONFIG, SslBundleSslEngineFactory.class)
                        .containsKey(SslBundle.class.getName());
            }
        });
    }

    @Test
    @DisplayName("settings of one client win over the common ones, as they do in Spring Boot")
    void aClientsOwnSettingsWin() {
        runner("spring.kafka.security.protocol=SASL_SSL", "spring.kafka.consumer.security.protocol=SSL",
                "spring.kafka.producer.bootstrap-servers=127.0.0.1:2", "spring.kafka.consumer.bootstrap-servers=127.0.0.1:3").run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(consumer(context)).containsEntry(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, "SSL")
                            .containsEntry(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, List.of("127.0.0.1:3"));
                    assertThat(producer(context)).containsEntry(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, "SASL_SSL")
                            .containsEntry(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, List.of("127.0.0.1:2"));
                });
    }

    @Test
    @DisplayName("what an application says of its consumer group and its reading stays the application's")
    void theApplicationsConsumerChoicesStand() {
        runner("spring.kafka.consumer.group-id=shop", "spring.kafka.consumer.auto-offset-reset=latest",
                "spring.kafka.consumer.max-poll-records=7").run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(consumer(context)).containsEntry(ConsumerConfig.GROUP_ID_CONFIG, "shop")
                            .containsEntry(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "latest")
                            .containsEntry(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, 7);
                });
    }

    @Test
    @DisplayName("max.poll.records in spring.kafka.consumer.properties keeps working")
    void maxPollRecordsThroughPropertiesKeepsWorking() {
        runner("spring.kafka.consumer.properties.max.poll.records=9").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(Integer.valueOf(consumer(context).get(ConsumerConfig.MAX_POLL_RECORDS_CONFIG).toString())).isEqualTo(9);
        });
    }

    @Test
    @DisplayName("an application that says nothing gets what Contexa ran with so far")
    void withoutSettingsTheDefaultsStand() {
        runner().run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(consumer(context)).containsEntry(ConsumerConfig.GROUP_ID_CONFIG, "security-plane-consumer")
                    .containsEntry(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest")
                    .containsEntry(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, false)
                    .containsEntry(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, 500);
            assertThat(producer(context)).containsEntry(ProducerConfig.ACKS_CONFIG, "all");
        });
    }

    @Test
    @DisplayName("an application with a name gets a consumer group of its own as the default")
    void aNamedApplicationHasADefaultGroupOfItsOwn() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            runner().run(context -> {
                assertThat(context).hasNotFailed();
                assertThat(consumer(context)).containsEntry(ConsumerConfig.GROUP_ID_CONFIG, "security-plane-consumer.shop");
            });
        }
    }

    @Test
    @DisplayName("Contexa's clients keep what its delivery depends on, whatever the application's Kafka says")
    void whatContexasDeliveryDependsOnStays() {
        runner("spring.kafka.consumer.key-deserializer=org.apache.kafka.common.serialization.ByteArrayDeserializer",
                "spring.kafka.consumer.value-deserializer=org.apache.kafka.common.serialization.ByteArrayDeserializer",
                "spring.kafka.consumer.enable-auto-commit=true",
                "spring.kafka.consumer.properties.metadata.max.age.ms=600000",
                "spring.kafka.producer.key-serializer=org.apache.kafka.common.serialization.ByteArraySerializer",
                "spring.kafka.producer.value-serializer=org.apache.kafka.common.serialization.ByteArraySerializer",
                "spring.kafka.producer.acks=0", "spring.kafka.producer.retries=0", "spring.kafka.producer.batch-size=1",
                "spring.kafka.producer.buffer-memory=1024",
                "spring.kafka.producer.properties.linger.ms=60000", "spring.kafka.producer.properties.max.block.ms=60000",
                "spring.kafka.producer.properties.request.timeout.ms=60000",
                "spring.kafka.producer.properties.delivery.timeout.ms=600000",
                "spring.kafka.producer.properties.transactional.id=shop-tx").run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(consumer(context)).containsEntry(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class)
                            .containsEntry(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class)
                            .containsEntry(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, false)
                            .containsEntry(ConsumerConfig.METADATA_MAX_AGE_CONFIG, 30_000);
                    assertThat(producer(context)).containsEntry(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class)
                            .containsEntry(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class)
                            .containsEntry(ProducerConfig.ACKS_CONFIG, "all")
                            .containsEntry(ProducerConfig.RETRIES_CONFIG, 3)
                            .containsEntry(ProducerConfig.BATCH_SIZE_CONFIG, 16384)
                            .containsEntry(ProducerConfig.BUFFER_MEMORY_CONFIG, 33554432)
                            .containsEntry(ProducerConfig.LINGER_MS_CONFIG, 10)
                            .containsEntry(ProducerConfig.MAX_BLOCK_MS_CONFIG, 3000)
                            .containsEntry(ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG, 5000)
                            .containsEntry(ProducerConfig.DELIVERY_TIMEOUT_MS_CONFIG, 10000)
                            .doesNotContainKey(ProducerConfig.TRANSACTIONAL_ID_CONFIG);
                });
    }

    @Test
    @DisplayName("Contexa's clients do not take the client id of the application's own")
    void theApplicationsClientIdIsNotShared() {
        runner("spring.kafka.client-id=shop").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(consumer(context)).containsEntry(CommonClientConfigs.CLIENT_ID_CONFIG, "shop-contexa");
            assertThat(producer(context)).containsEntry(CommonClientConfigs.CLIENT_ID_CONFIG, "shop-contexa");
        });
    }
}
