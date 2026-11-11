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
package io.contexa.contexacore.autonomous.event.listener;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacore.autonomous.event.SecurityEventListener;
import io.contexa.contexacore.autonomous.event.SecurityEventOrigin;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import org.apache.kafka.clients.admin.Admin;
import org.apache.kafka.clients.admin.AdminClientConfig;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.consumer.OffsetAndMetadata;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.serialization.Serializer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.annotation.EnableKafka;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.listener.ContainerProperties;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Applications on one Kafka cluster (CONTEXA_TEST_KAFKA_PORT, a broker of this test alone), the collector exactly as it
 * is declared: each application has topics of its own and is a group of its own, so each reads every partition of its
 * topic and nothing of the topics of the others; a record of another application that reached its topic all the same
 * is not analysed, and its offset moves on, so no group is left behind.
 */
@Timeout(value = 120, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
@EnabledIfEnvironmentVariable(named = KafkaSecurityEventCollectorBrokerApplicationTest.PORT, matches = "[0-9]+")
class KafkaSecurityEventCollectorBrokerApplicationTest {

    static final String PORT = "CONTEXA_TEST_KAFKA_PORT";
    private static final String BASE_GROUP = "security-plane-consumer";
    private static final int PARTITIONS = 3;

    /** Collects the users of the events of this test's topic that reached an application's analysis. */
    private static final class Analysis implements SecurityEventListener {
        final String topic;
        final List<String> users = new CopyOnWriteArrayList<>();

        Analysis(String topic) {
            this.topic = topic;
        }

        @Override
        public void onSecurityEvent(SecurityEvent event) {
            if (topic.equals(event.getMetadata().get("kafka.topic"))) {
                users.add(event.getUserId());
            }
        }
    }

    /** Reads a record whose text is the user: the format of an event is not what is under test. */
    private static final class UserPerRecord extends ObjectMapper {
        @Override
        public <T> T readValue(String content, Class<T> valueType) {
            return valueType.cast(ZeroTrustSpringEvent.builder("test").category(ZeroTrustEventCategory.AUTHORIZATION)
                    .eventType("METHOD").userId(content).sessionId("session").clientIp("10.0.0.1")
                    .payload(Map.of("action", "ALLOW")).build());
        }
    }

    @Configuration
    @EnableKafka
    static class Listening {

        static String bootstrap;
        static Analysis analysis;

        @Bean
        KafkaTemplate<String, Object> template() {
            Serializer<Object> values = (name, value) -> String.valueOf(value).getBytes(StandardCharsets.UTF_8);
            return new KafkaTemplate<>(new DefaultKafkaProducerFactory<>(producerConfig(), new StringSerializer(), values));
        }

        @Bean(name = "contexaKafkaListenerContainerFactory")
        ConcurrentKafkaListenerContainerFactory<String, String> contexaKafkaListenerContainerFactory() {
            Map<String, Object> config = new HashMap<>();
            config.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap);
            config.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
            config.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, false);
            config.put(ConsumerConfig.METADATA_MAX_AGE_CONFIG, 1000);
            ConcurrentKafkaListenerContainerFactory<String, String> factory = new ConcurrentKafkaListenerContainerFactory<>();
            factory.setConsumerFactory(new DefaultKafkaConsumerFactory<>(config, new StringDeserializer(), new StringDeserializer()));
            factory.getContainerProperties().setAckMode(ContainerProperties.AckMode.MANUAL);
            return factory;
        }

        @Bean
        KafkaSecurityEventCollector collector(KafkaTemplate<String, Object> template) {
            KafkaSecurityEventCollector collector =
                    new KafkaSecurityEventCollector(new UserPerRecord(), template, new SecurityKafkaProperties());
            collector.registerListener(analysis);
            return collector;
        }
    }

    private static Map<String, Object> producerConfig() {
        Map<String, Object> config = new HashMap<>();
        config.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, "127.0.0.1:" + System.getenv(PORT));
        config.put(ProducerConfig.ACKS_CONFIG, "all");
        return config;
    }

    private final String type = "ns" + UUID.randomUUID().toString().replace("-", "").substring(0, 12) + ".method";
    private final String bootstrap = "127.0.0.1:" + System.getenv(PORT);

    /** The topic of this test's events in the namespace of an application. */
    private String topicOf(String application) {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(application)) {
            return ApplicationNamespace.topic("security.events." + type);
        }
    }

    @Test
    @DisplayName("each application is a consumer group of its own that reads every partition of its own topic, analyses only its own events, and leaves no lag")
    void eachApplicationAnalysesOnlyItsOwnEvents() throws Exception {
        Map<String, String> topics = Map.of("shop", topicOf("shop"), "clinic", topicOf("clinic"), "", topicOf(""));
        assertThat(Set.copyOf(topics.values())).as("each application has a topic of its own").hasSize(3);
        try (Admin admin = Admin.create(Map.<String, Object>of(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap))) {
            admin.createTopics(topics.values().stream().map(topic -> new NewTopic(topic, PARTITIONS, (short) 1)).toList())
                    .all().get();
        }
        publish("shop", topics.get("shop"), "shop-", 9);
        publish("clinic", topics.get("clinic"), "clinic-", 9);
        publish("", topics.get(""), "nameless-", 3);
        // Records of another application that reached a topic they do not belong to.
        publish("clinic", topics.get("shop"), "stray-clinic-", 2);
        publish("shop", topics.get(""), "stray-shop-", 2);

        List<String> shop = runApplication("shop", topics.get("shop"));
        List<String> clinic = runApplication("clinic", topics.get("clinic"));
        List<String> nameless = runApplication("", topics.get(""));

        assertThat(shop).containsExactlyInAnyOrderElementsOf(users("shop-", 9));
        assertThat(clinic).containsExactlyInAnyOrderElementsOf(users("clinic-", 9));
        assertThat(nameless).containsExactlyInAnyOrderElementsOf(users("nameless-", 3));

        try (Admin admin = Admin.create(Map.<String, Object>of(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap))) {
            Set<String> groups = admin.listConsumerGroups().all().get().stream()
                    .map(group -> group.groupId()).collect(Collectors.toSet());
            assertThat(groups).contains(BASE_GROUP + ".shop", BASE_GROUP + ".clinic", BASE_GROUP);
            Map<String, String> groupOf = Map.of("shop", BASE_GROUP + ".shop", "clinic", BASE_GROUP + ".clinic", "", BASE_GROUP);
            for (Map.Entry<String, String> application : groupOf.entrySet()) {
                String group = application.getValue();
                String own = topics.get(application.getKey());
                assertThat(lagOnTheTopic(admin, group, own)).as("lag of %s on its topic", group).isZero();
                Set<String> read = admin.listConsumerGroupOffsets(group).partitionsToOffsetAndMetadata().get().keySet().stream()
                        .map(TopicPartition::topic).filter(topics::containsValue).collect(Collectors.toSet());
                assertThat(read).as("the topics of this test %s read", group).containsExactly(own);
            }
        }
    }

    private void publish(String application, String topic, String prefix, int count) throws Exception {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(application)) {
            KafkaTemplate<String, Object> template = new Listening().template();
            for (int index = 0; index < count; index++) {
                SecurityEventOrigin.send(template, topic, "key-" + index, prefix + index).get();
            }
            template.destroy();
        }
    }

    private static List<String> users(String prefix, int count) {
        return IntStream.range(0, count).mapToObj(index -> prefix + index).toList();
    }

    /** Starts the application under its name, lets it read its topic to its end, and returns who its analysis saw. */
    private List<String> runApplication(String name, String topic) throws Exception {
        Analysis analysis = new Analysis(topic);
        Listening.bootstrap = bootstrap;
        Listening.analysis = analysis;
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(name);
             AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(Listening.class)) {
            String group = ApplicationNamespace.consumerGroup(BASE_GROUP);
            try (Admin admin = Admin.create(Map.<String, Object>of(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap))) {
                Awaitility.await().atMost(Duration.ofSeconds(60)).pollInterval(Duration.ofMillis(500))
                        .until(() -> committedAll(admin, group, topic));
            }
            return new ArrayList<>(analysis.users);
        }
    }

    /** Whether the group has committed every record of its topic: the records of others included. */
    private boolean committedAll(Admin admin, String group, String topic) throws Exception {
        return lagOnTheTopic(admin, group, topic) == 0L && committedRecords(admin, group, topic) > 0L;
    }

    private long committedRecords(Admin admin, String group, String topic) throws Exception {
        return admin.listConsumerGroupOffsets(group).partitionsToOffsetAndMetadata().get().entrySet().stream()
                .filter(entry -> entry.getKey().topic().equals(topic)).mapToLong(entry -> entry.getValue().offset()).sum();
    }

    private long lagOnTheTopic(Admin admin, String group, String topic) throws Exception {
        Map<TopicPartition, OffsetAndMetadata> committed =
                admin.listConsumerGroupOffsets(group).partitionsToOffsetAndMetadata().get();
        Map<String, Object> config = new HashMap<>();
        config.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap);
        try (KafkaConsumer<String, String> reader =
                     new KafkaConsumer<>(config, new StringDeserializer(), new StringDeserializer())) {
            List<TopicPartition> partitions = IntStream.range(0, PARTITIONS).mapToObj(index -> new TopicPartition(topic, index)).toList();
            Map<TopicPartition, Long> ends = reader.endOffsets(partitions);
            long lag = 0;
            for (TopicPartition partition : partitions) {
                OffsetAndMetadata offset = committed.get(partition);
                lag += ends.get(partition) - (offset != null ? offset.offset() : 0L);
            }
            return lag;
        }
    }
}
