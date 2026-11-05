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
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.SecurityEventProcessor;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.config.AsyncConfig;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import org.apache.kafka.clients.admin.Admin;
import org.apache.kafka.clients.admin.AdminClientConfig;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.admin.OffsetSpec;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.OffsetAndMetadata;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.event.ConsumerPausedEvent;
import org.springframework.kafka.listener.AcknowledgingMessageListener;
import org.springframework.kafka.listener.ConcurrentMessageListenerContainer;
import org.springframework.kafka.listener.ContainerProperties;
import org.springframework.kafka.listener.DefaultErrorHandler;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.util.backoff.FixedBackOff;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Predicate;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Q-35 (PR-90): how long an event waits to be taken in while the analysis is behind, on a real broker, for when the
 * record is acknowledged. The collector, the monitoring queue, the agent and the analysis pool are Contexa's own, with
 * their default sizes; only the model is a timed stand-in, so nothing is paid for. Not a test: it is run by hand.
 * <p>
 * Arguments: the broker port, the file the results are appended to, then one case per argument, written
 * {@code arm:maxPollRecords:burst:modelMs:backlog:slowEvery:slowMs}. The arm is {@code immediate} (the record is
 * acknowledged when it is taken in, as today), {@code async} (Spring Kafka's asyncAcks, acknowledged once decided) or
 * {@code watermark} (no pause; the offset below every undecided record is acknowledged). The backlog is {@code first}
 * (sessions with no decision yet) or {@code decided} (sessions decided before).
 */
public final class AckTimingBrokerMeasure {

    private static final int DECIDED_SESSIONS = 256;
    private static final int PARTITIONS = 3;
    private static final long[] PROBE_DELAYS_MS = {2_000, 10_000};
    private static final long RUN_LIMIT_MS = 900_000;

    private record Case(String arm, int maxPoll, int burst, long modelMs, String backlog, int slowEvery, long slowMs) {

        static Case parse(String text) {
            String[] parts = text.split(":");
            return new Case(parts[0], Integer.parseInt(parts[1]), Integer.parseInt(parts[2]), Long.parseLong(parts[3]),
                    parts[4], Integer.parseInt(parts[5]), Long.parseLong(parts[6]));
        }
    }

    private record Probe(String id, long producedAt) {
    }

    /** Commits the offset below the first undecided record of a partition, whatever order the decisions come in. */
    private static final class Watermark {
        private final NavigableMap<Long, Acknowledgment> seen = new TreeMap<>();
        private final Set<Long> decided = ConcurrentHashMap.newKeySet();

        synchronized void seen(long offset, Acknowledgment acknowledgment) {
            seen.put(offset, acknowledgment);
        }

        synchronized void decided(long offset) {
            decided.add(offset);
            Acknowledgment last = null;
            while (!seen.isEmpty() && decided.remove(seen.firstKey())) {
                last = seen.pollFirstEntry().getValue();
            }
            if (last != null) {
                last.acknowledge();
            }
        }
    }

    private record Held(int partition, long offset, Acknowledgment acknowledgment) {
    }

    private AckTimingBrokerMeasure() {
    }

    public static void main(String[] args) throws Exception {
        String bootstrap = "127.0.0.1:" + args[0];
        Path out = Path.of(args[1]);
        for (int index = 2; index < args.length; index++) {
            String line = run(bootstrap, Case.parse(args[index]));
            System.out.println(line);
            Files.writeString(out, line + System.lineSeparator(), StandardCharsets.UTF_8, StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND);
        }
        System.exit(0);
    }

    private static String run(String bootstrap, Case measured) throws Exception {
        String topic = "security.events.authentication.measure-" + UUID.randomUUID();
        String group = "measure-" + UUID.randomUUID();
        try (Admin admin = Admin.create(Map.<String, Object>of(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap))) {
            admin.createTopics(List.of(new NewTopic(topic, PARTITIONS, (short) 1))).all().get();
        }

        Map<String, Long> ingested = new ConcurrentHashMap<>();
        Map<String, Long> started = new ConcurrentHashMap<>();
        Map<String, Long> finished = new ConcurrentHashMap<>();
        Map<String, Held> held = new ConcurrentHashMap<>();
        Map<Integer, Watermark> watermarks = new ConcurrentHashMap<>();
        AtomicLong slowOnes = new AtomicLong();
        AtomicInteger analysing = new AtomicInteger();
        AtomicInteger mostAnalysing = new AtomicInteger();
        AtomicInteger pauses = new AtomicInteger();
        boolean async = "async".equals(measured.arm());
        boolean watermark = "watermark".equals(measured.arm());

        SecurityEventProcessor processor = mock(SecurityEventProcessor.class);
        when(processor.process(any(SecurityEvent.class))).thenAnswer(call -> {
            SecurityEvent event = call.getArgument(0);
            String id = event.getEventId();
            started.put(id, System.currentTimeMillis());
            mostAnalysing.accumulateAndGet(analysing.incrementAndGet(), Math::max);
            boolean warm = id.startsWith("warm-");
            boolean slow = !warm && measured.slowEvery() > 0 && !id.startsWith("probe")
                    && slowOnes.incrementAndGet() % measured.slowEvery() == 0;
            Thread.sleep(warm ? 1L : slow ? measured.slowMs() : measured.modelMs());
            analysing.decrementAndGet();
            finished.put(id, System.currentTimeMillis());
            Held record = held.remove(id);
            if (record != null) {
                if (watermark) {
                    watermarks.get(record.partition()).decided(record.offset());
                } else {
                    record.acknowledgment().acknowledge();
                }
            }
            SecurityEventContext context = SecurityEventContext.builder().securityEvent(event)
                    .processingStatus(SecurityEventContext.ProcessingStatus.COMPLETED).build();
            context.addMetadata("processingResult",
                    ProcessingResult.builder().success(true).action("ALLOW").llmDecisionPresent(true).build());
            return context;
        });

        SecurityPlaneProperties properties = new SecurityPlaneProperties();
        ObjectMapper reader = new ObjectMapper() {
            @Override
            @SuppressWarnings("unchecked")
            public <T> T readValue(String content, Class<T> valueType) {
                String[] parts = content.split("\\|");
                return (T) ZeroTrustSpringEvent.builder(new Object()).category(ZeroTrustEventCategory.AUTHENTICATION)
                        .eventType(ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS).userId(parts[1]).sessionId(parts[2])
                        .clientIp("10.0.0.1").userAgent("measure").resource("/login").eventTimestamp(Instant.now())
                        .payload(Map.of("eventId", parts[0])).build();
            }
        };
        KafkaSecurityEventCollector collector =
                new KafkaSecurityEventCollector(reader, null, new SecurityKafkaProperties());
        SecurityMonitoringService monitor = new SecurityMonitoringService(collector, properties);
        ThreadPoolTaskExecutor pool = new AsyncConfig(properties).llmAnalysisExecutor();
        pool.afterPropertiesSet();
        SecurityPlaneAgent agent = new SecurityPlaneAgent(monitor, new InMemorySecurityContextDataStore(),
                mock(CentralAuditFacade.class), processor, properties, pool);
        agent.initialize();
        agent.start();
        monitor.initialize();

        AcknowledgingMessageListener<String, String> listener = (ConsumerRecord<String, String> record,
                                                                 Acknowledgment acknowledgment) -> {
            String id = record.value().split("\\|")[0];
            ingested.put(id, System.currentTimeMillis());
            if (async || watermark) {
                held.put(id, new Held(record.partition(), record.offset(), acknowledgment));
                if (watermark) {
                    watermarks.computeIfAbsent(record.partition(), ignored -> new Watermark())
                            .seen(record.offset(), acknowledgment);
                }
                collector.consumeZeroTrustEvents(record.value(), record.topic(), record.partition(), record.offset(), null);
            } else {
                collector.consumeZeroTrustEvents(record.value(), record.topic(), record.partition(), record.offset(),
                        acknowledgment);
            }
        };

        Map<String, Object> consumer = new HashMap<>();
        consumer.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap);
        consumer.put(ConsumerConfig.GROUP_ID_CONFIG, group);
        consumer.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        consumer.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, measured.maxPoll());
        consumer.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, false);
        consumer.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        consumer.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        ContainerProperties containerProperties = new ContainerProperties(topic);
        containerProperties.setAckMode(ContainerProperties.AckMode.MANUAL_IMMEDIATE);
        containerProperties.setAsyncAcks(async);
        containerProperties.setMessageListener(listener);
        ConcurrentMessageListenerContainer<String, String> container = new ConcurrentMessageListenerContainer<>(
                new DefaultKafkaConsumerFactory<>(consumer), containerProperties);
        container.setConcurrency(1);
        container.setCommonErrorHandler(new DefaultErrorHandler(new FixedBackOff(1000L, 3)));
        container.setApplicationEventPublisher(event -> {
            if (event instanceof ConsumerPausedEvent) {
                pauses.incrementAndGet();
            }
        });
        container.start();
        long waitedFrom = System.currentTimeMillis();
        while (container.getAssignedPartitions() == null || container.getAssignedPartitions().isEmpty()) {
            if (System.currentTimeMillis() - waitedFrom > 30_000) {
                throw new IllegalStateException("No partitions assigned");
            }
            Thread.sleep(50);
        }

        Map<String, Object> producerConfig = new HashMap<>();
        producerConfig.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap);
        producerConfig.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        producerConfig.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        producerConfig.put(ProducerConfig.LINGER_MS_CONFIG, 5);

        int expected = measured.burst() + PROBE_DELAYS_MS.length;
        List<Probe> probes = new ArrayList<>();
        // What a sensitive call meets while the backlog lasts: the gate of Q-23 reads isBehind().
        AtomicLong samples = new AtomicLong();
        AtomicLong behindSamples = new AtomicLong();
        AtomicInteger mostInProgress = new AtomicInteger();
        Thread sampler = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                if (!ingested.isEmpty() && finished.keySet().stream().filter(id -> !id.startsWith("warm-")).count() < expected) {
                    samples.incrementAndGet();
                    if (agent.isBehind()) {
                        behindSamples.incrementAndGet();
                    }
                    mostInProgress.accumulateAndGet(agent.analysesInProgress(), Math::max);
                }
                try {
                    Thread.sleep(100);
                } catch (InterruptedException stopped) {
                    return;
                }
            }
        });
        sampler.setDaemon(true);
        sampler.start();
        long burstAt;
        try (KafkaProducer<String, String> producer = new KafkaProducer<>(producerConfig)) {
            boolean decidedBacklog = "decided".equals(measured.backlog());
            if (decidedBacklog) {
                for (int session = 0; session < DECIDED_SESSIONS; session++) {
                    send(producer, topic, "warm-" + session, "user-" + session, "session-" + session);
                }
                producer.flush();
                awaitFinished(finished, id -> id.startsWith("warm-"), DECIDED_SESSIONS, 60_000);
            }
            burstAt = System.currentTimeMillis();
            for (int index = 0; index < measured.burst(); index++) {
                String user = decidedBacklog ? "user-" + index % DECIDED_SESSIONS : "user-" + index;
                String session = decidedBacklog ? "session-" + index % DECIDED_SESSIONS : "session-" + index;
                send(producer, topic, "event-" + index, user, session);
            }
            producer.flush();
            for (int index = 0; index < PROBE_DELAYS_MS.length; index++) {
                long at = burstAt + PROBE_DELAYS_MS[index];
                Thread.sleep(Math.max(0L, at - System.currentTimeMillis()));
                String id = "probe-" + index;
                probes.add(new Probe(id, System.currentTimeMillis()));
                send(producer, topic, id, "newcomer-" + index, "newcomer-session-" + index);
                producer.flush();
            }
        }

        boolean drained = awaitFinished(finished, id -> !id.startsWith("warm-"), expected, RUN_LIMIT_MS);
        long drainMs = finished.entrySet().stream().filter(entry -> !entry.getKey().startsWith("warm-"))
                .mapToLong(Map.Entry::getValue).max().orElse(burstAt) - burstAt;
        sampler.interrupt();
        Thread.sleep(1_500);

        long uncommitted = uncommitted(bootstrap, topic, group);
        StringBuilder probeReport = new StringBuilder();
        for (Probe probe : probes) {
            probeReport.append(String.format(Locale.ROOT, ", \"%s\": {\"takenInMs\": %d, \"startedMs\": %d, \"decidedMs\": %d}",
                    probe.id(), since(ingested, probe), since(started, probe), since(finished, probe)));
        }
        String line = String.format(Locale.ROOT,
                "{\"arm\": \"%s\", \"maxPollRecords\": %d, \"burst\": %d, \"modelMs\": %d, \"backlog\": \"%s\", "
                        + "\"slowEvery\": %d, \"slowMs\": %d, \"drained\": %s, \"decided\": %d, \"expected\": %d, "
                        + "\"drainMs\": %d, \"mostAnalysing\": %d, \"mostInProgress\": %d, \"behindShare\": %.3f, "
                        + "\"pauses\": %d, \"uncommittedAtEnd\": %d%s}",
                measured.arm(), measured.maxPoll(), measured.burst(), measured.modelMs(), measured.backlog(),
                measured.slowEvery(), measured.slowMs(), drained,
                finished.keySet().stream().filter(id -> !id.startsWith("warm-")).count(), expected, drainMs,
                mostAnalysing.get(), mostInProgress.get(),
                samples.get() == 0 ? 0.0 : (double) behindSamples.get() / samples.get(), pauses.get(), uncommitted,
                probeReport);

        container.stop();
        monitor.shutdown();
        agent.shutdown();
        pool.shutdown();
        return line;
    }

    private static long since(Map<String, Long> moments, Probe probe) {
        Long moment = moments.get(probe.id());
        return moment == null ? -1L : moment - probe.producedAt();
    }

    private static void send(KafkaProducer<String, String> producer, String topic, String id, String user, String session) {
        producer.send(new ProducerRecord<>(topic, session, id + "|" + user + "|" + session));
    }

    private static boolean awaitFinished(Map<String, Long> finished, Predicate<String> counted,
                                         int expected, long limitMs) throws InterruptedException {
        long until = System.currentTimeMillis() + limitMs;
        while (System.currentTimeMillis() < until) {
            if (finished.keySet().stream().filter(counted).count() >= expected) {
                return true;
            }
            Thread.sleep(20);
        }
        return false;
    }

    /** What the broker holds past the group's committed offsets: the records a crash now would redeliver. */
    private static long uncommitted(String bootstrap, String topic, String group) throws Exception {
        try (Admin admin = Admin.create(Map.<String, Object>of(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap))) {
            Map<TopicPartition, OffsetAndMetadata> committed =
                    admin.listConsumerGroupOffsets(group).partitionsToOffsetAndMetadata().get();
            Map<TopicPartition, OffsetSpec> latest = new HashMap<>();
            for (int partition = 0; partition < PARTITIONS; partition++) {
                latest.put(new TopicPartition(topic, partition), OffsetSpec.latest());
            }
            long left = 0;
            for (var end : admin.listOffsets(latest).all().get().entrySet()) {
                OffsetAndMetadata offset = committed.get(end.getKey());
                left += end.getValue().offset() - (offset != null ? offset.offset() : 0L);
            }
            return left;
        }
    }
}
