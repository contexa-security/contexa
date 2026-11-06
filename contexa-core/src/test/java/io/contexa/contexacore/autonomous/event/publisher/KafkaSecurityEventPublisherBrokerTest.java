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
package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacore.autonomous.event.SecurityEventTopics;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import org.apache.kafka.clients.admin.Admin;
import org.apache.kafka.clients.admin.AdminClientConfig;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.errors.TopicExistsException;
import org.apache.kafka.common.errors.UnknownTopicOrPartitionException;
import org.apache.kafka.common.serialization.Serializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Q-26 (PR-79) on a real broker with topic auto-creation off (CONTEXA_TEST_KAFKA_PORT, a broker of this test alone): how
 * a producer tells a topic it cannot find is the broker's to say, so what a test double says of it proves nothing. An
 * event must reach this node's analysis once, however the failure is told.
 */
@Timeout(value = 60, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
@EnabledIfEnvironmentVariable(named = KafkaSecurityEventPublisherBrokerTest.PORT, matches = "[0-9]+")
class KafkaSecurityEventPublisherBrokerTest {

    static final String PORT = "CONTEXA_TEST_KAFKA_PORT";

    private final List<ZeroTrustSpringEvent> analysedHere = new CopyOnWriteArrayList<>();
    private final String topic = SecurityEventTopics.of(ZeroTrustEventCategory.AUTHENTICATION,
            ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS);
    private DefaultKafkaProducerFactory<String, Object> producers;
    private KafkaSecurityEventPublisher publisher;

    private static String bootstrap() {
        return "127.0.0.1:" + System.getenv(PORT);
    }

    private static Admin admin() {
        return Admin.create(Map.<String, Object>of(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap()));
    }

    @BeforeEach
    void setUp() {
        Map<String, Object> config = new HashMap<>();
        config.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap());
        config.put(ProducerConfig.MAX_BLOCK_MS_CONFIG, 1000);
        config.put(ProducerConfig.DELIVERY_TIMEOUT_MS_CONFIG, 3000);
        config.put(ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG, 2000);
        Serializer<Object> values = (name, value) -> String.valueOf(value).getBytes(StandardCharsets.UTF_8);
        producers = new DefaultKafkaProducerFactory<>(config, new StringSerializer(), values);
        publisher = new KafkaSecurityEventPublisher(new KafkaTemplate<>(producers), new SecurityKafkaProperties());
        publisher.setLocalAnalysis(analysedHere::add);
    }

    @AfterEach
    void close() throws Exception {
        publisher.destroy();
        producers.destroy();
    }

    private static ZeroTrustSpringEvent event() {
        return ZeroTrustSpringEvent.builder(new Object()).category(ZeroTrustEventCategory.AUTHENTICATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS).userId("alice").sessionId("session-1")
                .clientIp("10.0.0.1").userAgent("client").resource("/login").payload(Map.of("authMethod", "form"))
                .build();
    }

    private void theTopicIsGone() throws Exception {
        try (Admin admin = admin()) {
            admin.deleteTopics(List.of(topic)).all().get();
        } catch (ExecutionException failure) {
            if (!(failure.getCause() instanceof UnknownTopicOrPartitionException)) {
                throw failure;
            }
        }
        try (Admin admin = admin()) {
            Awaitility.await().atMost(Duration.ofSeconds(20)).until(() -> !admin.listTopics().names().get().contains(topic));
        }
    }

    private void theTopicIsThere() throws Exception {
        try (Admin admin = admin()) {
            admin.createTopics(List.of(new NewTopic(topic, 1, (short) 1))).all().get();
        } catch (ExecutionException failure) {
            if (!(failure.getCause() instanceof TopicExistsException)) {
                throw failure;
            }
        }
    }

    @Test
    void anEventWhoseTopicIsMissingIsAnalysedHereOnce() throws Exception {
        theTopicIsGone();

        publisher.publishGenericSecurityEvent(event());

        Awaitility.await().atMost(Duration.ofSeconds(15)).untilAsserted(() -> assertThat(analysedHere).hasSize(1));
        Thread.sleep(3_000);
        assertThat(analysedHere).as("told once, whichever way the producer tells it").hasSize(1);
        assertThat(publisher.getStatistics()).containsEntry("publish_failed_count", 1L)
                .containsEntry("analysed_here_count", 1L);
    }

    @Test
    void anEventKafkaTakesIsNotAnalysedHere() throws Exception {
        theTopicIsThere();

        publisher.publishGenericSecurityEvent(event());

        Awaitility.await().atMost(Duration.ofSeconds(15)).untilAsserted(() ->
                assertThat(publisher.getStatistics()).containsEntry("publish_confirmed_count", 1L));
        assertThat(analysedHere).isEmpty();
    }
}
