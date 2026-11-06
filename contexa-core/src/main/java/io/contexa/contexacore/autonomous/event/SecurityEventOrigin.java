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
package io.contexa.contexacore.autonomous.event;

import io.contexa.contexacommon.store.ApplicationNamespace;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.header.Header;
import org.apache.kafka.common.header.Headers;
import org.apache.kafka.common.header.internals.RecordHeader;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Which application a security event on Kafka belongs to. The topics are shared by every application on the cluster, and
 * the consumer group of each application is its own, so every application reads every event; the application that
 * published an event is the one that analyses it. An application with a name stamps what it publishes with its name
 * ({@value #HEADER}); each reads only the events that carry its own name, or, without a name, none.
 */
public final class SecurityEventOrigin {

    /** The Kafka header that carries the name of the application an event belongs to. */
    public static final String HEADER = "ctxa-app";

    private SecurityEventOrigin() {
    }

    /** The headers of an event this application publishes: its name when it has one, and none without. */
    public static List<Header> headers() {
        if (!ApplicationNamespace.isNamed()) {
            return List.of();
        }
        return List.of(new RecordHeader(HEADER, ApplicationNamespace.identifier().getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Sends a value stamped with the name of this application. Without a name the template is called as it always was, so
     * that what an application without a name puts on the wire does not change.
     */
    public static CompletableFuture<SendResult<String, Object>> send(KafkaTemplate<String, Object> template, String topic,
                                                                     String key, Object value) {
        List<Header> origin = headers();
        if (origin.isEmpty()) {
            return key != null ? template.send(topic, key, value) : template.send(topic, value);
        }
        return template.send(new ProducerRecord<>(topic, null, null, key, value, origin));
    }

    /**
     * Whether a record belongs to this application: it carries the application's name, or, for an application without a
     * name, carries no name. {@code headers} are those of the Kafka record, or {@code null} for a record that has none.
     */
    public static boolean isOwn(Headers headers) {
        return ApplicationNamespace.identifier().equals(nameIn(headers));
    }

    /** The name a record carries, or the empty string when it carries none. */
    public static String nameIn(Headers headers) {
        Header header = headers != null ? headers.lastHeader(HEADER) : null;
        return header != null && header.value() != null ? new String(header.value(), StandardCharsets.UTF_8) : "";
    }
}
