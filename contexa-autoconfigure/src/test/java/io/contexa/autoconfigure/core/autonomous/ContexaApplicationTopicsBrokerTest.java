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
import io.contexa.autoconfigure.core.infra.ApplicationNamespacePostProcessor;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacore.autonomous.event.SecurityEventListener;
import io.contexa.contexacore.autonomous.event.SecurityEventOrigin;
import io.contexa.contexacore.autonomous.event.SecurityEventTopics;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.listener.KafkaSecurityEventCollector;
import io.contexa.contexacore.autonomous.event.publisher.KafkaSecurityEventPublisher;
import io.contexa.contexacore.config.ApplicationConfig;
import io.contexa.contexacore.config.KafkaTopicConfiguration;
import io.contexa.contexacore.infra.kafka.KafkaConfiguration;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import org.apache.kafka.clients.admin.Admin;
import org.apache.kafka.clients.admin.AdminClientConfig;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.header.internals.RecordHeader;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.kafka.KafkaAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.KafkaListenerEndpointRegistry;
import org.springframework.kafka.listener.MessageListenerContainer;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Applications that share one Kafka cluster (CONTEXA_TEST_KAFKA_PORT, a broker of this test alone, with topic
 * auto-creation off), with Contexa's own topic admin, producer, consumer and collector as the distributed mode wires
 * them: each application makes and uses topics of its own under {@code ctxa.<name>.}, subscribes to nothing of another,
 * and the servers of one application share theirs. The name of the application comes from {@code spring.application.name}
 * the way Spring Boot binds it at start. A name is bound for the whole JVM, so applications of different names run one
 * after another here, and the records another application publishes reach its topics while the first one runs.
 */
@Timeout(value = 240, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
@EnabledIfEnvironmentVariable(named = ContexaApplicationTopicsBrokerTest.PORT, matches = "[0-9]+")
class ContexaApplicationTopicsBrokerTest {

    static final String PORT = "CONTEXA_TEST_KAFKA_PORT";
    private static final Duration WAIT = Duration.ofSeconds(60);
    /** The topics Contexa makes at start: the three of declared events and the dead letters, which are all it uses. */
    private static final int TOPICS_MADE = 4;

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(SecurityKafkaProperties.class)
    static class ContexaSide {
        @Bean(name = "contexaObjectMapper", defaultCandidate = false)
        ObjectMapper contexaObjectMapper() {
            return new ApplicationConfig().objectMapper();
        }
    }

    /** Who the analysis of an application saw, with the topic each event came from. */
    private static final class Analysis implements SecurityEventListener {
        final Map<String, String> topicOfUser = new ConcurrentHashMap<>();
        final List<String> users = Collections.synchronizedList(new ArrayList<>());

        @Override
        public void onSecurityEvent(SecurityEvent event) {
            users.add(event.getUserId());
            topicOfUser.put(event.getUserId(), String.valueOf(event.getMetadata().get("kafka.topic")));
        }
    }

    /** An application while it runs: its context, what its analysis saw, and how it publishes. */
    private static final class Live {
        final AssertableApplicationContext context;
        final Analysis analysis = new Analysis();

        Live(AssertableApplicationContext context) {
            this.context = context;
            assertThat(context).hasNotFailed();
            context.getBean(KafkaSecurityEventCollector.class).registerListener(analysis);
        }

        void publish(ZeroTrustEventCategory category, String type, String user) {
            context.getBean(KafkaSecurityEventPublisher.class).publishGenericSecurityEvent(event(category, type, user));
        }

        Set<TopicPartition> assigned() {
            Set<TopicPartition> assigned = new HashSet<>();
            for (MessageListenerContainer container : context.getBean(KafkaListenerEndpointRegistry.class).getListenerContainers()) {
                Collection<TopicPartition> partitions = container.getAssignedPartitions();
                if (partitions != null) {
                    assigned.addAll(partitions);
                }
            }
            return assigned;
        }

        Set<String> assignedTopics() {
            return assigned().stream().map(TopicPartition::topic).collect(Collectors.toCollection(TreeSet::new));
        }

        Map<String, Object> statistics() {
            return context.getBean(KafkaSecurityEventCollector.class).getStatistics();
        }
    }

    private final String run = UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    private static String bootstrap() {
        return "127.0.0.1:" + System.getenv(PORT);
    }

    private static Admin admin() {
        return Admin.create(Map.<String, Object>of(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap()));
    }

    private static Set<String> topicsOnTheBroker() throws Exception {
        try (Admin admin = admin()) {
            return admin.listTopics().names().get(20, TimeUnit.SECONDS);
        }
    }

    private static ZeroTrustSpringEvent event(ZeroTrustEventCategory category, String type, String user) {
        return ZeroTrustSpringEvent.builder("topics-test").category(category).eventType(type).userId(user)
                .sessionId("session-" + user).clientIp("10.0.0.1").userAgent("topics-test").resource("/orders")
                .payload(Map.of("action", "ALLOW")).build();
    }

    /** The distributed mode of an application named as Spring Boot names it, at the start of its context. */
    private ApplicationContextRunner application(String name, String... properties) {
        List<String> values = new ArrayList<>(List.of("contexa.infrastructure.mode=distributed",
                "spring.kafka.bootstrap-servers=" + bootstrap(),
                "spring.kafka.consumer.properties.session.timeout.ms=6000",
                "spring.kafka.consumer.properties.heartbeat.interval.ms=1000"));
        if (name != null) {
            values.add("spring.application.name=" + name);
        }
        values.addAll(List.of(properties));
        return new ApplicationContextRunner()
                .withInitializer(context -> new ApplicationNamespacePostProcessor()
                        .postProcessEnvironment(context.getEnvironment(), null))
                .withPropertyValues(values.toArray(String[]::new))
                .withUserConfiguration(ContexaSide.class, KafkaConfiguration.class, KafkaTopicConfiguration.class)
                .withConfiguration(AutoConfigurations.of(KafkaAutoConfiguration.class,
                        CoreAutonomousEventAutoConfiguration.KafkaEventConfiguration.class));
    }

    /** Runs an application and gives back the name bound before it, whatever it bound. */
    private void running(ApplicationContextRunner application, ThrowingConsumer<Live> body) {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(null)) {
            application.run(context -> {
                Live live = new Live(context);
                Awaitility.await().atMost(WAIT).pollInterval(Duration.ofMillis(200)).until(() -> !live.assigned().isEmpty());
                body.accept(live);
            });
        }
    }

    @FunctionalInterface
    private interface ThrowingConsumer<T> {
        void accept(T value) throws Exception;
    }

    /** The prefix of an application's topics, computed as the application computes it. */
    private static String prefixOf(String name) {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(name)) {
            return ApplicationNamespace.topic("");
        }
    }

    /** The topics an application of this prefix makes at start: those of its declared events, and its dead letters. */
    private static List<String> topicsMadeBy(String prefix) {
        return List.of(prefix + "security.events.authentication.success", prefix + "security.events.authentication.mfa",
                prefix + "security.events.authorization.method", prefix + "security-events-dlq");
    }

    private static String eventTopicOf(String name, ZeroTrustEventCategory category, String type) {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using(name)) {
            return SecurityEventTopics.of(category, type);
        }
    }

    /** What a server of another application publishes: its event, stamped with its name, on its topic. */
    private static void publishAs(String name, ZeroTrustEventCategory category, String type, String... users) throws Exception {
        String topic = eventTopicOf(name, category, type);
        byte[] origin = ApplicationNamespace.normalize(name).getBytes(StandardCharsets.UTF_8);
        ObjectMapper json = new ApplicationConfig().objectMapper();
        Map<String, Object> config = new HashMap<>();
        config.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap());
        config.put(ProducerConfig.ACKS_CONFIG, "all");
        try (KafkaProducer<String, String> producer = new KafkaProducer<>(config, new StringSerializer(), new StringSerializer())) {
            for (String user : users) {
                ProducerRecord<String, String> record = new ProducerRecord<>(topic, "session-" + user,
                        json.writeValueAsString(event(category, type, user)));
                record.headers().add(new RecordHeader(SecurityEventOrigin.HEADER, origin));
                producer.send(record).get(20, TimeUnit.SECONDS);
            }
        }
    }

    /** The topics of which a consumer group committed an offset. */
    private static Set<String> committedTopics(String group) throws Exception {
        try (Admin admin = admin()) {
            return admin.listConsumerGroupOffsets(group).partitionsToOffsetAndMetadata().get(20, TimeUnit.SECONDS).keySet()
                    .stream().map(TopicPartition::topic).collect(Collectors.toCollection(TreeSet::new));
        }
    }

    private static Map<TopicPartition, Long> endOffsets(Collection<TopicPartition> partitions) {
        Map<String, Object> config = new HashMap<>();
        config.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap());
        try (KafkaConsumer<String, String> reader = new KafkaConsumer<>(config, new StringDeserializer(), new StringDeserializer())) {
            return reader.endOffsets(partitions);
        }
    }

    @Test
    @DisplayName("two applications on one cluster make, write and read topics of their own, and neither reads a record of the other")
    void twoApplicationsUseTopicsOfTheirOwn() throws Exception {
        String clinic = "Clinic_" + run;
        String shop = "shop-" + run;
        String clinicPrefix = "ctxa.clinic_5f" + run + ".";
        String shopPrefix = "ctxa.shop-" + run + ".";
        assertThat(prefixOf(clinic)).isEqualTo(clinicPrefix);
        assertThat(prefixOf(shop)).isEqualTo(shopPrefix);
        String hostTopic = "host.events." + run;
        try (Admin admin = admin()) {
            admin.createTopics(List.of(new NewTopic(hostTopic, 2, (short) 1))).all().get(20, TimeUnit.SECONDS);
        }

        Set<String> before = topicsOnTheBroker();
        running(application(clinic), live -> {
            Set<String> made = new TreeSet<>(topicsOnTheBroker());
            made.removeAll(before);
            assertThat(made).as("the topics the first application made").hasSize(TOPICS_MADE)
                    .containsExactlyInAnyOrderElementsOf(topicsMadeBy(clinicPrefix));
            assertThat(live.assignedTopics()).allMatch(topic -> topic.startsWith(clinicPrefix + "security.events."));

            live.publish(ZeroTrustEventCategory.AUTHENTICATION, ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS, "clinic-a1");
            live.publish(ZeroTrustEventCategory.AUTHORIZATION, ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD, "clinic-a2");
            Awaitility.await().atMost(WAIT).until(() -> live.analysis.users.size() >= 2);
            assertThat(live.analysis.topicOfUser).containsOnlyKeys("clinic-a1", "clinic-a2")
                    .allSatisfy((user, topic) -> assertThat(topic).startsWith(clinicPrefix));
        });

        Set<String> beforeShop = topicsOnTheBroker();
        running(application(shop), live -> {
            Set<String> made = new TreeSet<>(topicsOnTheBroker());
            made.removeAll(beforeShop);
            assertThat(made).as("the topics the second application made").hasSize(TOPICS_MADE)
                    .containsExactlyInAnyOrderElementsOf(topicsMadeBy(shopPrefix));
            Set<String> shopTopics = live.assignedTopics();
            assertThat(shopTopics).isNotEmpty().allMatch(topic -> topic.startsWith(shopPrefix + "security.events."));

            live.publish(ZeroTrustEventCategory.AUTHENTICATION, ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS, "shop-b1");
            live.publish(ZeroTrustEventCategory.AUTHORIZATION, ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD, "shop-b2");
            // A server of the first application is at work at the same time.
            publishAs(clinic, ZeroTrustEventCategory.AUTHENTICATION, ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS,
                    "clinic-c1", "clinic-c2");
            publishAs(clinic, ZeroTrustEventCategory.AUTHORIZATION, ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD, "clinic-c3");

            Awaitility.await().atMost(WAIT).until(() -> live.analysis.users.size() >= 2);
            String shopGroup = "security-plane-consumer." + ApplicationNamespace.identifier();
            Awaitility.await().atMost(WAIT).pollInterval(Duration.ofMillis(500)).until(() -> {
                Set<TopicPartition> partitions = live.assigned();
                Map<TopicPartition, Long> ends = endOffsets(partitions);
                try (Admin admin = admin()) {
                    var committed = admin.listConsumerGroupOffsets(shopGroup).partitionsToOffsetAndMetadata()
                            .get(20, TimeUnit.SECONDS);
                    return partitions.stream().allMatch(partition -> ends.get(partition) == 0L
                            || committed.get(partition) != null && committed.get(partition).offset() == ends.get(partition));
                }
            });
            assertThat(live.analysis.users).containsExactlyInAnyOrder("shop-b1", "shop-b2");
            assertThat(live.analysis.topicOfUser.values()).allMatch(topic -> topic.startsWith(shopPrefix));
            assertThat(live.statistics()).as("the second application never received a record of the first")
                    .containsEntry("other_application_events_skipped", 0L).containsEntry("error_count", 0L);
            assertThat(committedTopics(shopGroup)).isNotEmpty().allMatch(topic -> topic.startsWith(shopPrefix));
            assertThat(live.assignedTopics()).doesNotContain(hostTopic);
        });

        running(application(clinic), live -> {
            Awaitility.await().atMost(WAIT).until(() -> live.analysis.users.size() >= 3);
            Thread.sleep(2_000);
            assertThat(live.analysis.users).as("what the first application's servers published while the second ran")
                    .containsExactlyInAnyOrder("clinic-c1", "clinic-c2", "clinic-c3");
            assertThat(live.statistics()).containsEntry("other_application_events_skipped", 0L).containsEntry("error_count", 0L);
            String clinicGroup = "security-plane-consumer." + ApplicationNamespace.identifier();
            assertThat(committedTopics(clinicGroup)).isNotEmpty().allMatch(topic -> topic.startsWith(clinicPrefix));
        });

        try (Admin admin = admin()) {
            assertThat(admin.describeTopics(List.of(hostTopic)).allTopicNames().get(20, TimeUnit.SECONDS).get(hostTopic)
                    .partitions()).as("the application's own topic is as it made it").hasSize(2);
        }
    }

    @Test
    @DisplayName("the servers of one application make the same topics, split their partitions and analyse each event once")
    void theServersOfOneApplicationShareTheirTopics() throws Exception {
        String ward = "ward-" + run;
        String wardPrefix = "ctxa.ward-" + run + ".";
        running(application(ward), first -> {
            Set<String> topicsAfterTheFirst = topicsOnTheBroker();
            application(ward).run(context -> {
                Live second = new Live(context);
                assertThat(topicsOnTheBroker()).as("the second server makes no topic of its own").isEqualTo(topicsAfterTheFirst);
                Set<TopicPartition> all = new HashSet<>();
                for (String topic : SecurityEventTopics.declared()) {
                    for (int partition = 0; partition < 3; partition++) {
                        all.add(new TopicPartition(topic, partition));
                    }
                }
                Awaitility.await().atMost(WAIT).pollInterval(Duration.ofMillis(200)).until(() -> {
                    Set<TopicPartition> one = first.assigned();
                    Set<TopicPartition> two = second.assigned();
                    Set<TopicPartition> both = new HashSet<>(one);
                    both.addAll(two);
                    return !one.isEmpty() && !two.isEmpty() && both.equals(all) && one.size() + two.size() == all.size();
                });
                assertThat(first.assignedTopics()).allMatch(topic -> topic.startsWith(wardPrefix));
                assertThat(second.assignedTopics()).allMatch(topic -> topic.startsWith(wardPrefix));

                List<String> users = new ArrayList<>();
                for (int index = 0; index < 9; index++) {
                    users.add("ward-u" + index);
                    first.publish(ZeroTrustEventCategory.AUTHORIZATION, ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD,
                            "ward-u" + index);
                }
                Awaitility.await().atMost(WAIT)
                        .until(() -> first.analysis.users.size() + second.analysis.users.size() >= users.size());
                Thread.sleep(2_000);
                List<String> analysed = new ArrayList<>(first.analysis.users);
                analysed.addAll(second.analysis.users);
                assertThat(analysed).as("each event once, on one of the servers").containsExactlyInAnyOrderElementsOf(users);
            });
        });
    }

    @Test
    @DisplayName("an application without a name reads Contexa's topics only, not a topic named as an application that is not Contexa names it")
    void anApplicationWithoutANameReadsNoTopicOfAnotherKind() throws Exception {
        String foreign = "security.events.orders.created-" + run;
        try (Admin admin = admin()) {
            admin.createTopics(List.of(new NewTopic(foreign, 1, (short) 1))).all().get(20, TimeUnit.SECONDS);
        }
        running(application(null, "security.plane.kafka.group-id=unnamed-" + run,
                "spring.kafka.consumer.auto-offset-reset=latest"), live -> {
            assertThat(ApplicationNamespace.isNamed()).isFalse();
            assertThat(topicsOnTheBroker()).contains("ctxa.security.events.authentication.success", "ctxa.security-events-dlq");
            Awaitility.await().atMost(WAIT).pollInterval(Duration.ofMillis(200))
                    .until(() -> live.assignedTopics().containsAll(SecurityEventTopics.declared()));
            // The group starts at the end of each partition: what is written from here on is what it reads.
            Thread.sleep(3_000);
            Map<String, Object> config = new HashMap<>();
            config.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap());
            try (KafkaProducer<String, String> producer = new KafkaProducer<>(config, new StringSerializer(), new StringSerializer())) {
                producer.send(new ProducerRecord<>(foreign, "order-42", "order 42 was created")).get(20, TimeUnit.SECONDS);
            }
            String user = "nameless-" + run;
            live.publish(ZeroTrustEventCategory.AUTHENTICATION, ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS, user);
            Awaitility.await().atMost(WAIT).until(() -> live.analysis.users.contains(user));
            Thread.sleep(2_000);

            assertThat(live.assignedTopics()).allMatch(topic -> topic.startsWith("ctxa.security.events.")).doesNotContain(foreign);
            assertThat(live.statistics()).containsEntry("error_count", 0L).containsEntry("dlq_dispatch_requested_count", 0L);
            assertThat(committedTopics("unnamed-" + run)).doesNotContain(foreign);
        });
    }

    @Test
    @DisplayName("a topic name the operator set is made and used as it is set, and the dead letters go there")
    void aTopicNameTheOperatorSetIsUsedAsItIs() throws Exception {
        String audit = "audit-" + run;
        String legacy = "security-events-dlq-" + run;
        running(application(audit, "contexa.security.kafka.topic.dlq=" + legacy), live -> {
            Set<String> topics = topicsOnTheBroker();
            assertThat(topics).contains(legacy, "ctxa.audit-" + run + ".security.events.authorization.method")
                    .doesNotContain("ctxa.audit-" + run + ".security-events-dlq");

            // A record of this application that cannot be read is sent to the dead letters.
            Map<String, Object> config = new HashMap<>();
            config.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap());
            try (KafkaProducer<String, String> producer = new KafkaProducer<>(config, new StringSerializer(), new StringSerializer())) {
                ProducerRecord<String, String> record = new ProducerRecord<>(
                        eventTopicOf(audit, ZeroTrustEventCategory.AUTHORIZATION, ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD),
                        "session-x", "not an event");
                record.headers().add(new RecordHeader(SecurityEventOrigin.HEADER,
                        ApplicationNamespace.identifier().getBytes(StandardCharsets.UTF_8)));
                producer.send(record).get(20, TimeUnit.SECONDS);
            }
            Awaitility.await().atMost(WAIT).until(() -> ((Long) live.statistics().get("dlq_dispatch_confirmed_count")) > 0L);

            Map<String, Object> readerConfig = new HashMap<>();
            readerConfig.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap());
            try (KafkaConsumer<String, String> reader =
                         new KafkaConsumer<>(readerConfig, new StringDeserializer(), new StringDeserializer())) {
                TopicPartition deadLetters = new TopicPartition(legacy, 0);
                reader.assign(List.of(deadLetters));
                reader.seekToBeginning(List.of(deadLetters));
                List<ConsumerRecord<String, String>> read = new ArrayList<>();
                long deadline = System.nanoTime() + WAIT.toNanos();
                while (read.isEmpty() && System.nanoTime() < deadline) {
                    reader.poll(Duration.ofMillis(200)).forEach(read::add);
                }
                assertThat(read).isNotEmpty().allSatisfy(record -> assertThat(record.value()).contains("not an event"));
            }
        });
    }

    @Test
    @DisplayName("a topic nothing writes to or reads is not made, whether it has the default name or one the operator set")
    void aTopicNothingUsesIsNotMade() throws Exception {
        String lean = "lean-" + run;
        String prefix = "ctxa.lean-" + run + ".";
        List<String> unused = List.of("auth-events-critical", "auth-events-contextual", "auth-events-general",
                "security-authorization-events", "security-incident-events", "security-audit-events", "security-events",
                "threat-indicators", "network-events", "soar-action-events");
        List<String> named = List.of("ops-authorization-" + run, "ops-authentication-" + run, "ops-incident-" + run,
                "ops-threat-" + run, "ops-audit-" + run, "ops-general-" + run, "ops-soar-" + run);
        String deadLetters = "ops-dead-letters-" + run;

        Set<String> before = topicsOnTheBroker();
        running(application(lean, "contexa.security.kafka.topic.dlq=" + deadLetters,
                "contexa.security.kafka.topic.authorization=" + named.get(0),
                "contexa.security.kafka.topic.authentication=" + named.get(1),
                "contexa.security.kafka.topic.incident=" + named.get(2),
                "contexa.security.kafka.topic.threat=" + named.get(3),
                "contexa.security.kafka.topic.audit=" + named.get(4),
                "contexa.security.kafka.topic.general=" + named.get(5),
                "contexa.security.kafka.topic.soar-action=" + named.get(6)), live -> {
            Set<String> made = new TreeSet<>(topicsOnTheBroker());
            made.removeAll(before);
            assertThat(made).as("the topics the application made").containsExactlyInAnyOrder(
                    prefix + "security.events.authentication.success", prefix + "security.events.authentication.mfa",
                    prefix + "security.events.authorization.method", deadLetters);
            assertThat(made).doesNotContainAnyElementsOf(named);
            unused.forEach(topic -> assertThat(made).doesNotContain(prefix + topic, topic, "ctxa." + topic));

            // What is made is what the application uses: an event is written, read and analysed.
            live.publish(ZeroTrustEventCategory.AUTHENTICATION, ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS, "lean-a1");
            live.publish(ZeroTrustEventCategory.AUTHENTICATION, ZeroTrustSpringEvent.TYPE_AUTHENTICATION_MFA, "lean-a2");
            live.publish(ZeroTrustEventCategory.AUTHORIZATION, ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD, "lean-a3");
            Awaitility.await().atMost(WAIT).until(() -> live.analysis.users.size() >= 3);
            assertThat(live.analysis.users).containsExactlyInAnyOrder("lean-a1", "lean-a2", "lean-a3");
            assertThat(live.analysis.topicOfUser.values()).allMatch(topic -> topic.startsWith(prefix + "security.events."));
            assertThat(live.statistics()).containsEntry("error_count", 0L).containsEntry("dlq_dispatch_requested_count", 0L);
        });

        Set<String> after = topicsOnTheBroker();
        assertThat(after).doesNotContainAnyElementsOf(named);
        unused.forEach(topic -> assertThat(after).doesNotContain(prefix + topic));
    }
}
