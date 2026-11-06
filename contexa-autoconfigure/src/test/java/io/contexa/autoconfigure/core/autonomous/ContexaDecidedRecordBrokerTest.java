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

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.contexa.contexacommon.config.redis.ContexaJsonRedisSerializer;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.SecurityEventProcessor;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.listener.KafkaSecurityEventCollector;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.store.RedisSecurityContextDataStore;
import io.contexa.contexacore.infra.kafka.KafkaConfiguration;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import org.apache.kafka.clients.admin.Admin;
import org.apache.kafka.clients.admin.AdminClientConfig;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.consumer.OffsetAndMetadata;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.serialization.StringSerializer;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.kafka.KafkaAutoConfiguration;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.kafka.config.KafkaListenerEndpointRegistry;
import org.springframework.kafka.listener.MessageListenerContainer;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * On a real broker and a real Redis, with Contexa's own container factory and listener: what a node had not finished is
 * delivered again and decided, what it had finished costs no second model call, and the commit never goes past an event
 * the analysis still holds. The model is a stand-in. CONTEXA_TEST_KAFKA_DECIDED_PORT: a broker of this test alone;
 * CONTEXA_TEST_REDIS_PORT: its Redis.
 */
@EnabledIfEnvironmentVariable(named = ContexaDecidedRecordBrokerTest.PORT, matches = "[0-9]+")
class ContexaDecidedRecordBrokerTest {

    static final String PORT = "CONTEXA_TEST_KAFKA_DECIDED_PORT";
    private static final Duration WAIT = Duration.ofSeconds(60);

    private static LettuceConnectionFactory connections;
    private static RedisTemplate<String, Object> redis;

    /** The event of the record's value: its id, then the user and the session. */
    private static final class RecordReader extends ObjectMapper {
        @Override
        @SuppressWarnings("unchecked")
        public <T> T readValue(String content, Class<T> valueType) throws JsonProcessingException {
            String[] parts = content.split("\\|");
            if (parts.length < 3) {
                throw new JsonParseException(null, "Not an event: " + content);
            }
            return (T) ZeroTrustSpringEvent.builder(new Object()).category(ZeroTrustEventCategory.AUTHENTICATION)
                    .eventType(ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS).userId(parts[1]).sessionId(parts[2])
                    .clientIp("10.0.0.1").userAgent("broker-test").resource("/login").eventTimestamp(Instant.now())
                    .payload(Map.of("eventId", parts[0])).build();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class ContexaSide {
        @Bean(name = "contexaObjectMapper", defaultCandidate = false)
        ObjectMapper contexaObjectMapper() {
            return new RecordReader();
        }

        @Bean
        SecurityKafkaProperties securityKafkaProperties() {
            return new SecurityKafkaProperties();
        }
    }

    /** A node: Contexa's consumer and collector from the context, the queue, the agent and a store of its own. */
    private final class Node {
        private final KafkaListenerEndpointRegistry registry;
        private final RedisSecurityContextDataStore store = new RedisSecurityContextDataStore(redis);
        private final SecurityMonitoringService monitor;
        private final SecurityPlaneAgent agent;
        private final ExecutorService analysis = Executors.newCachedThreadPool();
        private final Map<String, AtomicInteger> calls = new ConcurrentHashMap<>();

        private Node(AssertableApplicationContext context) throws Exception {
            registry = context.getBean(KafkaListenerEndpointRegistry.class);
            SecurityEventProcessor model = mock(SecurityEventProcessor.class);
            when(model.process(any(SecurityEvent.class))).thenAnswer(call -> {
                SecurityEvent event = call.getArgument(0);
                calls.computeIfAbsent(event.getEventId(), id -> new AtomicInteger()).incrementAndGet();
                allCalls.computeIfAbsent(event.getEventId(), id -> new AtomicInteger()).incrementAndGet();
                CountDownLatch held = holds.get(event.getEventId());
                if (held != null && nodes.get(0) == this) {
                    held.await();
                }
                SecurityEventContext decided = SecurityEventContext.builder().securityEvent(event)
                        .processingStatus(SecurityEventContext.ProcessingStatus.COMPLETED).build();
                decided.addMetadata("processingResult",
                        ProcessingResult.builder().success(true).action("ALLOW").llmDecisionPresent(true).build());
                return decided;
            });
            SecurityPlaneProperties properties = new SecurityPlaneProperties();
            KafkaSecurityEventCollector collector = context.getBean(KafkaSecurityEventCollector.class);
            monitor = new SecurityMonitoringService(collector, properties);
            agent = new SecurityPlaneAgent(monitor, store, mock(CentralAuditFacade.class), model, properties, analysis);
            agent.initialize();
            agent.start();
            monitor.initialize();
            nodes.add(this);
            Awaitility.await().atMost(WAIT).until(this::readsTheTopic);
        }

        private boolean readsTheTopic() {
            for (MessageListenerContainer container : registry.getListenerContainers()) {
                Collection<TopicPartition> assigned = container.getAssignedPartitions();
                if (assigned != null && assigned.stream().anyMatch(partition -> partition.topic().equals(topic))) {
                    return true;
                }
            }
            return false;
        }

        /** Nothing more of this node reaches the broker. What it wrote to Redis stays. */
        private void stopsReading() {
            registry.stop();
        }

        private void dies() {
            stopsReading();
            store.close();
        }

        private void stop() {
            registry.stop();
            monitor.shutdown();
            agent.shutdown();
            store.close();
            analysis.shutdownNow();
        }
    }

    private final Map<String, AtomicInteger> allCalls = new ConcurrentHashMap<>();
    /** What the first node's model does not answer until told. */
    private final Map<String, CountDownLatch> holds = new ConcurrentHashMap<>();
    private final List<Node> nodes = new CopyOnWriteArrayList<>();
    private String topic;
    private String group;
    private String prefix;

    @BeforeAll
    static void connect() {
        connections = new LettuceConnectionFactory(new RedisStandaloneConfiguration(
                "127.0.0.1", Integer.parseInt(System.getenv("CONTEXA_TEST_REDIS_PORT"))));
        connections.afterPropertiesSet();
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        mapper.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
        GenericJackson2JsonRedisSerializer values =
                new ContexaJsonRedisSerializer(ContexaJsonRedisSerializer.activateDefaultTyping(mapper));
        redis = new RedisTemplate<>();
        redis.setConnectionFactory(connections);
        redis.setKeySerializer(new StringRedisSerializer());
        redis.setHashKeySerializer(new StringRedisSerializer());
        redis.setValueSerializer(values);
        redis.setHashValueSerializer(values);
        redis.setDefaultSerializer(values);
        redis.afterPropertiesSet();
    }

    @AfterAll
    static void disconnect() {
        connections.destroy();
    }

    private static String bootstrap() {
        return "127.0.0.1:" + System.getenv(PORT);
    }

    private static Admin admin() {
        return Admin.create(Map.<String, Object>of(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap()));
    }

    @BeforeEach
    void names() {
        prefix = UUID.randomUUID().toString();
        topic = "security.events.authentication.decided-" + prefix;
        group = "decided-" + prefix;
    }

    @AfterEach
    void release() {
        holds.values().forEach(CountDownLatch::countDown);
        nodes.forEach(Node::stop);
    }

    private void makeTheTopic(int partitions) throws Exception {
        try (Admin admin = admin()) {
            admin.createTopics(List.of(new NewTopic(topic, partitions, (short) 1))).all().get();
        }
    }

    private ApplicationContextRunner runner() {
        return new ApplicationContextRunner()
                .withPropertyValues("contexa.infrastructure.mode=distributed", "spring.kafka.bootstrap-servers=" + bootstrap(),
                        "spring.kafka.consumer.auto-offset-reset=latest", "security.plane.kafka.group-id=" + group,
                        "spring.kafka.consumer.properties.session.timeout.ms=6000",
                        "spring.kafka.consumer.properties.heartbeat.interval.ms=1000")
                .withUserConfiguration(ContexaSide.class, KafkaConfiguration.class)
                .withConfiguration(AutoConfigurations.of(KafkaAutoConfiguration.class,
                        CoreAutonomousEventAutoConfiguration.KafkaEventConfiguration.class));
    }

    private String id(int index) {
        return prefix + "-" + index;
    }

    private void publish(int partition, int... indexes) {
        Map<String, Object> config = new HashMap<>();
        config.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap());
        config.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        config.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        try (KafkaProducer<String, String> producer = new KafkaProducer<>(config)) {
            for (int index : indexes) {
                producer.send(new ProducerRecord<>(topic, partition, "key", id(index) + "|user-" + index + "|session-" + index));
            }
            producer.flush();
        }
    }

    private void publishValue(int partition, String value) {
        Map<String, Object> config = new HashMap<>();
        config.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap());
        config.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        config.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        try (KafkaProducer<String, String> producer = new KafkaProducer<>(config)) {
            producer.send(new ProducerRecord<>(topic, partition, "key", value));
            producer.flush();
        }
    }

    private long committed(int partition) throws Exception {
        try (Admin admin = admin()) {
            OffsetAndMetadata offset = admin.listConsumerGroupOffsets(group).partitionsToOffsetAndMetadata().get()
                    .get(new TopicPartition(topic, partition));
            return offset != null ? offset.offset() : -1L;
        }
    }

    private void awaitCommitted(int partition, long offset) {
        Awaitility.await().atMost(WAIT).pollInterval(Duration.ofMillis(200)).until(() -> committed(partition) == offset);
    }

    private void awaitAsked(int count) {
        Awaitility.await().atMost(WAIT).pollInterval(Duration.ofMillis(50))
                .until(() -> allCalls.keySet().stream().filter(id -> id.startsWith(prefix)).count() >= count);
    }

    private int asked(int index) {
        AtomicInteger calls = allCalls.get(id(index));
        return calls != null ? calls.get() : 0;
    }

    /** The node goes on reading past the undecided record, and the next one decides what it left and nothing else. */
    @Test
    void whatANodeHadNotFinishedIsDecidedByTheNextOneAndNothingElseIsAskedAgain() throws Exception {
        makeTheTopic(1);
        holds.put(id(3), new CountDownLatch(1));

        runner().run(firstContext -> {
            Node first = new Node(firstContext);
            publish(0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9);

            awaitAsked(10);
            awaitCommitted(0, 3);
            Thread.sleep(1_000);
            assertThat(committed(0)).as("the commit stays below the undecided record").isEqualTo(3);

            first.dies();

            runner().run(nextContext -> {
                Node next = new Node(nextContext);

                awaitCommitted(0, 10);

                assertThat(next.calls.keySet()).as("only what was not finished reaches the model").containsExactly(id(3));
                assertThat(asked(3)).isEqualTo(2);
                for (int index : new int[] {0, 1, 2, 4, 5, 6, 7, 8, 9}) {
                    assertThat(asked(index)).as("event " + index).isEqualTo(1);
                }
            });
        });
    }

    /** The first node stopped reading and still decides: the next one waits for it and does not ask the model again. */
    @Test
    void anEventItsFirstNodeStillDecidesIsNotAskedAgain() throws Exception {
        makeTheTopic(1);
        CountDownLatch deciding = new CountDownLatch(1);
        holds.put(id(0), deciding);

        runner().run(firstContext -> {
            Node first = new Node(firstContext);
            publish(0, 0, 1);
            awaitAsked(2);
            first.stopsReading();

            runner().run(nextContext -> {
                new Node(nextContext);
                Thread.sleep(2_000);
                deciding.countDown();

                awaitCommitted(0, 2);

                assertThat(asked(0)).isEqualTo(1);
                assertThat(asked(1)).isEqualTo(1);
            });
        });
    }

    /** A node joins while another holds undecided records: every record is decided once and everything is committed. */
    @Test
    void aRebalanceLosesNoDecisionAndRepeatsNone() throws Exception {
        makeTheTopic(2);
        CountDownLatch deciding = new CountDownLatch(1);
        holds.put(id(0), deciding);

        runner().run(firstContext -> {
            new Node(firstContext);
            publish(0, 0, 1, 2);
            publish(1, 3, 4, 5);
            awaitAsked(6);
            assertThat(committed(0)).as("0 is undecided on its partition").isLessThanOrEqualTo(0);

            runner().run(nextContext -> {
                new Node(nextContext);
                Thread.sleep(2_000);
                deciding.countDown();

                awaitCommitted(0, 3);
                awaitCommitted(1, 3);

                for (int index = 0; index < 6; index++) {
                    assertThat(asked(index)).as("event " + index).isEqualTo(1);
                }
            });
        });
    }

    /** A record no event can be read from fails, is retried, goes to the dead letters and holds nothing back. */
    @Test
    void whatCannotBeReadDoesNotHoldTheCommit() throws Exception {
        makeTheTopic(1);

        runner().run(context -> {
            new Node(context);
            publish(0, 0);
            publishValue(0, "not an event");
            publish(0, 2);

            awaitCommitted(0, 3);

            assertThat(asked(0)).isEqualTo(1);
            assertThat(asked(2)).isEqualTo(1);
        });
    }
}
