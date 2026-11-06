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
import io.contexa.contexacore.autonomous.event.SecurityEventListener;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import org.junit.jupiter.api.Test;
import org.springframework.kafka.core.KafkaTemplate;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/** Q-26 (PR-79): an event Kafka did not take reaches the listeners of this node as a consumed event does. */
class KafkaSecurityEventCollectorLocalAnalysisTest {

    @SuppressWarnings("unchecked")
    private final KafkaSecurityEventCollector collector = new KafkaSecurityEventCollector(new ObjectMapper(),
            mock(KafkaTemplate.class), new SecurityKafkaProperties());
    private final List<SecurityEvent> received = new CopyOnWriteArrayList<>();

    private static ZeroTrustSpringEvent event() {
        return ZeroTrustSpringEvent.builder(new Object()).category(ZeroTrustEventCategory.AUTHENTICATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS).userId("alice").sessionId("session-1")
                .clientIp("10.0.0.1").payload(Map.of("eventId", "event-1")).build();
    }

    @Test
    void itReachesTheListenersWithTheFactsAConsumedEventHas() {
        collector.registerListener(new SecurityEventListener() {
            @Override
            public void onSecurityEvent(SecurityEvent event) {
                received.add(event);
            }

            @Override
            public String getListenerName() {
                return "test";
            }
        });

        collector.analyseHere(event());

        assertThat(received).hasSize(1);
        SecurityEvent event = received.get(0);
        assertThat(event.getEventId()).isEqualTo("event-1");
        assertThat(event.getUserId()).isEqualTo("alice");
        assertThat(event.getMetadata())
                .containsEntry("zerotrust.category", "AUTHENTICATION")
                .containsEntry("zerotrust.eventType", "SUCCESS")
                .containsEntry(KafkaSecurityEventCollector.ANALYSED_ON_THE_PUBLISHING_NODE, true)
                .containsKey("ingestAt");
        assertThat(collector.getStatistics()).containsEntry("total_events", 1L);
    }

    @Test
    void aListenerThatFailsIsToldToTheCaller() {
        collector.registerListener(new SecurityEventListener() {
            @Override
            public void onSecurityEvent(SecurityEvent event) {
                throw new IllegalStateException("queue");
            }

            @Override
            public String getListenerName() {
                return "test";
            }
        });

        assertThatThrownBy(() -> collector.analyseHere(event())).isInstanceOf(IllegalStateException.class);
    }
}
