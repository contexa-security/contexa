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

import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.admin.Admin;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.common.KafkaFuture;
import org.apache.kafka.common.errors.TopicExistsException;
import org.springframework.beans.factory.SmartInitializingSingleton;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * Makes Contexa's Kafka topics when the application starts, before its listener containers start. A consumer that
 * joined with nothing to read finds a new topic only at its next metadata refresh, and a broker that does not create
 * topics on first use would never have them (PR-73, PR-79).
 * <p>
 * The application's {@code KafkaAdmin} is not asked to do it: the {@code NewTopics} it collects fail the application's
 * start under {@code spring.kafka.admin.fail-fast} when one cannot be made, and it waits half a minute for a broker
 * that is down. Here a topic that cannot be made is named once at start and the application goes on. A topic that
 * exists is left as it is; {@code spring.kafka.admin.auto-create=false} is obeyed.
 */
@Slf4j
public class ContexaKafkaTopics implements SmartInitializingSingleton {

    /** The longest the start waits for one answer of the broker. */
    public static final Duration ANSWER_LIMIT = Duration.ofSeconds(5);
    private static final Duration CLOSE_LIMIT = Duration.ofSeconds(1);

    private final Supplier<Admin> admins;
    private final List<NewTopic> topics;
    private final boolean create;

    /**
     * @param admins makes the admin client, which this closes
     * @param topics every topic to make, each one something reads or writes: any of them that is missing is reported
     * @param create false when the application forbids making topics: they are only checked
     */
    public ContexaKafkaTopics(Supplier<Admin> admins, List<NewTopic> topics, boolean create) {
        this.admins = admins;
        this.topics = List.copyOf(topics);
        this.create = create;
    }

    @Override
    public void afterSingletonsInstantiated() {
        Map<String, String> missing = provision();
        if (!missing.isEmpty()) {
            log.error("[ContexaKafkaTopics] Kafka topics Contexa needs are missing: {} ({}). Until a topic exists its "
                            + "events are not published and reach no analysis. The application goes on starting.",
                    String.join(", ", missing.keySet()), String.join("; ", new TreeSet<>(missing.values())));
        }
    }

    /** The topics that are not on the broker after this, each with why. */
    Map<String, String> provision() {
        Map<String, String> missing = new TreeMap<>();
        Admin admin = null;
        try {
            admin = admins.get();
            Set<String> held = admin.listTopics().names().get(ANSWER_LIMIT.toMillis(), TimeUnit.MILLISECONDS);
            List<NewTopic> absent = topics.stream().filter(topic -> !held.contains(topic.name())).toList();
            if (create) {
                make(admin, absent, missing);
            } else {
                absent.forEach(topic -> missing.put(topic.name(), "spring.kafka.admin.auto-create is false"));
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            topics.forEach(topic -> missing.put(topic.name(), "not checked: the start was interrupted"));
        } catch (Exception failure) {
            String cause = "not checked: " + cause(failure);
            topics.forEach(topic -> missing.put(topic.name(), cause));
        } finally {
            close(admin);
        }
        return missing;
    }

    private void make(Admin admin, List<NewTopic> absent, Map<String, String> missing) throws InterruptedException {
        if (absent.isEmpty()) {
            return;
        }
        Map<String, KafkaFuture<Void>> made = admin.createTopics(absent).values();
        long deadline = System.nanoTime() + ANSWER_LIMIT.toNanos();
        for (Map.Entry<String, KafkaFuture<Void>> topic : made.entrySet()) {
            try {
                topic.getValue().get(Math.max(0L, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
            } catch (ExecutionException failure) {
                // Another node of the application made it first.
                if (!(failure.getCause() instanceof TopicExistsException)) {
                    missing.put(topic.getKey(), cause(failure.getCause()));
                }
            } catch (TimeoutException noAnswer) {
                missing.put(topic.getKey(), cause(noAnswer));
            }
        }
    }

    private static void close(Admin admin) {
        if (admin == null) {
            return;
        }
        try {
            admin.close(CLOSE_LIMIT);
        } catch (RuntimeException failure) {
            log.debug("[ContexaKafkaTopics] The admin client did not close cleanly", failure);
        }
    }

    /** The failure on one line: this is reported in one line of the start's log. */
    private static String cause(Throwable failure) {
        Throwable root = failure instanceof ExecutionException && failure.getCause() != null
                ? failure.getCause() : failure;
        String message = root.getMessage() != null ? root.getMessage().lines().collect(Collectors.joining(" ")) : "";
        return root.getClass().getSimpleName() + (message.isBlank() ? "" : ": " + message);
    }
}
