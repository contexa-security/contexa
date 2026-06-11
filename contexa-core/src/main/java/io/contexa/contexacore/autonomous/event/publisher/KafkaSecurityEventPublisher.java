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

import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;

import io.contexa.contexacore.properties.SecurityKafkaProperties;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@RequiredArgsConstructor
public class KafkaSecurityEventPublisher implements SecurityEventPublisher {

    private final KafkaTemplate<String, Object> kafkaTemplate;
    private final SecurityKafkaProperties securityKafkaProperties;
    private final AtomicLong publishRequestedCount = new AtomicLong(0);
    private final AtomicLong publishConfirmedCount = new AtomicLong(0);
    private final AtomicLong publishFailedCount = new AtomicLong(0);
    private final AtomicLong dlqDispatchRequestedCount = new AtomicLong(0);
    private final AtomicLong dlqDispatchConfirmedCount = new AtomicLong(0);
    private final AtomicLong dlqDispatchFailedCount = new AtomicLong(0);

    @Override
    public void publishGenericSecurityEvent(ZeroTrustSpringEvent event) {
        long startTime = System.currentTimeMillis();
        publishRequestedCount.incrementAndGet();

            String topic = String.format("security.events.%s.%s",
                    event.getCategory().name().toLowerCase(),
                    event.getEventType().toLowerCase());

            String key = generateEventKey(event);
            CompletableFuture<SendResult<String, Object>> future = kafkaTemplate.send(topic, key, event);
            future.whenComplete((result, ex) -> {
                if(ex != null) {
                    publishFailedCount.incrementAndGet();
                    long duration = System.currentTimeMillis() - startTime;
                    log.error("[KafkaPublisher] Failed to publish ZeroTrust event - category={}, type={}, error: {}, duration={}ms",
                            event.getCategory(), event.getEventType(), ex.getMessage(), duration, ex);
                    sendToDeadLetterQueueAsync(event, ex);
                    return;
                }
                publishConfirmedCount.incrementAndGet();
            });
    }

    private String generateEventKey(ZeroTrustSpringEvent event) {
        if (event.getSessionId() != null && !event.getSessionId().isEmpty()) {
            return event.getSessionId();
        }
        if (event.getUserId() != null && !event.getUserId().isEmpty()) {
            return event.getUserId();
        }
        return "unknown-" + System.currentTimeMillis();
    }

    private void sendToDeadLetterQueueAsync(Object event, Throwable exception) {
        try {
            DeadLetterEvent dlqEvent = DeadLetterEvent.builder()
                    .originalEvent(event)
                    .errorMessage(exception.getMessage())
                    .errorType(exception.getClass().getName())
                    .build();

            dlqDispatchRequestedCount.incrementAndGet();
            kafkaTemplate.send(securityKafkaProperties.getTopic().getDlq(), dlqEvent)
                    .whenComplete((result, dlqError) -> {
                        if (dlqError == null) {
                            dlqDispatchConfirmedCount.incrementAndGet();
                            log.error("Event sent to Dead Letter Queue: {}", event);
                            return;
                        }
                        dlqDispatchFailedCount.incrementAndGet();
                        log.error("Failed to dispatch event to Dead Letter Queue", dlqError);
                    });
        } catch (Exception e) {
            dlqDispatchFailedCount.incrementAndGet();
            log.error("Failed to send event to Dead Letter Queue", e);
        }
    }

    Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("publish_requested_count", publishRequestedCount.get());
        stats.put("publish_confirmed_count", publishConfirmedCount.get());
        stats.put("publish_failed_count", publishFailedCount.get());
        stats.put("dlq_dispatch_requested_count", dlqDispatchRequestedCount.get());
        stats.put("dlq_dispatch_confirmed_count", dlqDispatchConfirmedCount.get());
        stats.put("dlq_dispatch_failed_count", dlqDispatchFailedCount.get());
        return stats;
    }

    @Data
    @Builder
    private static class DeadLetterEvent {
        private Object originalEvent;
        private String errorMessage;
        private String errorType;
        @Builder.Default
        private long timestamp = System.currentTimeMillis();
    }
}
