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
import io.contexa.contexacore.autonomous.event.SecurityEventTopics;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.publisher.KafkaSecurityEventPublisher;
import io.contexa.contexacore.config.KafkaTopicConfiguration;
import io.contexa.contexacore.infra.kafka.KafkaConfiguration;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import org.apache.kafka.clients.admin.Admin;
import org.apache.kafka.clients.admin.AdminClientConfig;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.TopicPartition;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.kafka.KafkaAutoConfiguration;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.KafkaTemplate;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * PR-73, PR-79 on real brokers. CONTEXA_TEST_KAFKA_PORT: a broker of this test alone, with topic auto-creation off; the
 * test deletes the security event topics on it first. CONTEXA_TEST_KAFKA_REFUSING_PORT: one that refuses new topics.
 */
@ExtendWith(OutputCaptureExtension.class)
class ContexaKafkaTopicsBrokerTest {

    private static final String PORT = "CONTEXA_TEST_KAFKA_PORT";
    private static final String REFUSING_PORT = "CONTEXA_TEST_KAFKA_REFUSING_PORT";
    private static final String DEAD_LETTER_TOPIC = "security-events-dlq";

    @Configuration(proxyBeanMethods = false)
    static class ContexaSide {
        @Bean(name = "contexaObjectMapper", defaultCandidate = false)
        ObjectMapper contexaObjectMapper() {
            return new ObjectMapper().findAndRegisterModules();
        }
    }

    private static String bootstrap(String variable) {
        return "127.0.0.1:" + System.getenv(variable);
    }

    private ApplicationContextRunner runner(String bootstrap) {
        return new ApplicationContextRunner()
                .withPropertyValues("contexa.infrastructure.mode=distributed", "spring.kafka.bootstrap-servers=" + bootstrap,
                        "spring.kafka.admin.fail-fast=true")
                .withUserConfiguration(ContexaSide.class, KafkaConfiguration.class, KafkaTopicConfiguration.class)
                .withConfiguration(AutoConfigurations.of(KafkaAutoConfiguration.class));
    }

    private static Admin admin(String bootstrap) {
        return Admin.create(Map.of(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap));
    }

    private static void deleteSecurityEventTopics(String bootstrap) throws Exception {
        try (Admin admin = admin(bootstrap)) {
            Set<String> existing = admin.listTopics().names().get();
            List<String> own = existing.stream().filter(name -> name.startsWith("security.events.")).toList();
            if (!own.isEmpty()) {
                admin.deleteTopics(own).all().get();
                Awaitility.await().atMost(Duration.ofSeconds(30)).until(() ->
                        admin.listTopics().names().get().stream().noneMatch(name -> name.startsWith("security.events.")));
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static KafkaSecurityEventPublisher publisher(AssertableApplicationContext context) {
        return new KafkaSecurityEventPublisher(context.getBean("contexaKafkaTemplate", KafkaTemplate.class),
                new SecurityKafkaProperties());
    }

    @SuppressWarnings("unchecked")
    private static Consumer<String, String> consumer(AssertableApplicationContext context) {
        return ((ConsumerFactory<String, String>) context.getBean("contexaConsumerFactory", ConsumerFactory.class))
                .createConsumer("topics-test-" + UUID.randomUUID(), "topics-test");
    }

    private static ZeroTrustSpringEvent event(ZeroTrustEventCategory category, String type) {
        return ZeroTrustSpringEvent.builder("topics-test").category(category).eventType(type)
                .userId("broker-user").sessionId("broker-session").clientIp("127.0.0.1").payload(Map.of("action", "ALLOW"))
                .build();
    }

    private static List<ConsumerRecord<String, String>> pollUntilRead(Consumer<String, String> consumer, String topic,
                                                                      Duration limit) {
        List<ConsumerRecord<String, String>> read = new ArrayList<>();
        long deadline = System.nanoTime() + limit.toNanos();
        while (read.isEmpty() && System.nanoTime() < deadline) {
            consumer.poll(Duration.ofMillis(200)).forEach(record -> {
                if (record.topic().equals(topic)) {
                    read.add(record);
                }
            });
        }
        return read;
    }

    /** A first deployment on a broker that creates nothing itself: the first event is read in seconds, not minutes. */
    @Test
    @EnabledIfEnvironmentVariable(named = PORT, matches = "[0-9]+")
    void onABrokerWithoutAutoCreationTheFirstEventIsReadAtOnce(CapturedOutput output) throws Exception {
        String bootstrap = bootstrap(PORT);
        deleteSecurityEventTopics(bootstrap);

        runner(bootstrap).run(context -> {
            assertThat(context).hasNotFailed();
            try (Admin admin = admin(bootstrap)) {
                assertThat(admin.listTopics().names().get()).containsAll(SecurityEventTopics.DECLARED)
                        .contains(DEAD_LETTER_TOPIC);
            }
            KafkaSecurityEventPublisher publisher = publisher(context);
            try (Consumer<String, String> consumer = consumer(context)) {
                consumer.subscribe(Pattern.compile(SecurityEventTopics.PATTERN));
                long began = System.nanoTime();
                Awaitility.await().atMost(Duration.ofSeconds(15)).pollDelay(Duration.ZERO).until(() -> {
                    consumer.poll(Duration.ofMillis(200));
                    return !consumer.assignment().isEmpty();
                });
                Set<String> assigned = consumer.assignment().stream().map(TopicPartition::topic).collect(Collectors.toSet());
                assertThat(assigned).containsExactlyInAnyOrderElementsOf(new HashSet<>(SecurityEventTopics.DECLARED));

                String topic = SecurityEventTopics.of(ZeroTrustEventCategory.AUTHENTICATION,
                        ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS);
                publisher.publishGenericSecurityEvent(event(ZeroTrustEventCategory.AUTHENTICATION,
                        ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS));

                assertThat(pollUntilRead(consumer, topic, Duration.ofSeconds(15))).hasSize(1);
                assertThat(Duration.ofNanos(System.nanoTime() - began)).isLessThan(Duration.ofSeconds(30));
            } finally {
                publisher.destroy();
            }
        });
        assertThat(output.getOut() + output.getErr()).doesNotContain("[ContexaKafkaTopics]");
    }

    /** A topic that appears after the consumer joined, an application's own type, is found at the next look. */
    @Test
    @EnabledIfEnvironmentVariable(named = PORT, matches = "[0-9]+")
    void aTopicThatAppearsLaterIsReadWithinTheDiscoveryInterval() throws Exception {
        String bootstrap = bootstrap(PORT);
        String type = "LATE-" + UUID.randomUUID();
        String topic = SecurityEventTopics.of(ZeroTrustEventCategory.CUSTOM, type);

        runner(bootstrap).run(context -> {
            assertThat(context).hasNotFailed();
            KafkaSecurityEventPublisher publisher = publisher(context);
            try (Consumer<String, String> consumer = consumer(context); Admin admin = admin(bootstrap)) {
                consumer.subscribe(Pattern.compile(SecurityEventTopics.PATTERN));
                Awaitility.await().atMost(Duration.ofSeconds(15)).pollDelay(Duration.ZERO).until(() -> {
                    consumer.poll(Duration.ofMillis(200));
                    return !consumer.assignment().isEmpty();
                });
                admin.createTopics(List.of(new NewTopic(topic, 1, (short) 1))).all().get();
                publisher.publishGenericSecurityEvent(event(ZeroTrustEventCategory.CUSTOM, type));

                assertThat(pollUntilRead(consumer, topic, Duration.ofSeconds(60))).hasSize(1);
            } finally {
                publisher.destroy();
            }
        });
    }

    /** A broker that refuses the topics: the application starts, the topics are named, and a request is not held. */
    @Test
    @EnabledIfEnvironmentVariable(named = REFUSING_PORT, matches = "[0-9]+")
    void aBrokerThatRefusesTheTopicsStopsNoStartAndHoldsNoRequest(CapturedOutput output) {
        runner(bootstrap(REFUSING_PORT)).run(context -> {
            assertThat(context).hasNotFailed();
            KafkaSecurityEventPublisher publisher = publisher(context);
            try {
                long began = System.nanoTime();
                for (int call = 0; call < 5; call++) {
                    publisher.publishGenericSecurityEvent(event(ZeroTrustEventCategory.AUTHENTICATION,
                            ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS));
                }
                assertThat(Duration.ofNanos(System.nanoTime() - began)).isLessThan(Duration.ofMillis(500));
            } finally {
                publisher.destroy();
            }
        });
        List<String> reported = (output.getOut() + output.getErr()).lines()
                .filter(line -> line.contains("[ContexaKafkaTopics]")).toList();
        assertThat(reported).hasSize(1);
        assertThat(reported.get(0)).contains(SecurityEventTopics.DECLARED);
    }
}
