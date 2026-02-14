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

import java.util.concurrent.CompletableFuture;

@Slf4j
@RequiredArgsConstructor
public class KafkaSecurityEventPublisher implements SecurityEventPublisher {

    private final KafkaTemplate<String, Object> kafkaTemplate;
    private final SecurityKafkaProperties securityKafkaProperties;

    @Override
    public void publishGenericSecurityEvent(ZeroTrustSpringEvent event) {
        long startTime = System.currentTimeMillis();

            String topic = String.format("security.events.%s.%s",
                    event.getCategory().name().toLowerCase(),
                    event.getEventType().toLowerCase());

            String key = generateEventKey(event);
            CompletableFuture<SendResult<String, Object>> future = kafkaTemplate.send(topic, key, event);
            future.whenComplete((result, ex) -> {
                if(ex != null) {
                    long duration = System.currentTimeMillis() - startTime;
                    log.error("[KafkaPublisher] Failed to publish ZeroTrust event - category={}, type={}, error: {}, duration={}ms",
                            event.getCategory(), event.getEventType(), ex.getMessage(), duration, ex);
                    sendToDeadLetterQueue(event, ex);
                }
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

    private void sendToDeadLetterQueue(Object event, Throwable exception) {
        try {
            DeadLetterEvent dlqEvent = DeadLetterEvent.builder()
                    .originalEvent(event)
                    .errorMessage(exception.getMessage())
                    .errorType(exception.getClass().getName())
                    .build();

            kafkaTemplate.send(securityKafkaProperties.getTopic().getDlq(), dlqEvent);
            log.error("Event sent to Dead Letter Queue: {}", event);
        } catch (Exception e) {
            log.error("Failed to send event to Dead Letter Queue", e);
        }
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
