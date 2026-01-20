package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;

import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;

import java.util.concurrent.CompletableFuture;


@Slf4j
@RequiredArgsConstructor
public class KafkaSecurityEventPublisher implements SecurityEventPublisher {

    private final KafkaTemplate<String, Object> kafkaTemplate;

    @Value("${security.kafka.topic.dlq:security-events-dlq}")
    private String deadLetterTopic;

    
    @Override
    public void publishGenericSecurityEvent(ZeroTrustSpringEvent event) {
        long startTime = System.currentTimeMillis();

        try {
            
            String topic = String.format("security.events.%s.%s",
                    event.getCategory().name().toLowerCase(),
                    event.getEventType().toLowerCase());

            String key = generateEventKey(event);

            log.debug("[KafkaPublisher] Publishing ZeroTrust event - category={}, type={}, user={}, topic={}",
                    event.getCategory(), event.getEventType(), event.getUserId(), topic);

            CompletableFuture<SendResult<String, Object>> future =
                    kafkaTemplate.send(topic, key, event);

            future.whenComplete((result, ex) -> {
                long duration = System.currentTimeMillis() - startTime;
                if (ex == null) {
                    log.debug("[KafkaPublisher] ZeroTrust event published - category={}, type={}, topic={}, duration={}ms",
                            event.getCategory(), event.getEventType(), topic, duration);
                } else {
                    log.error("[KafkaPublisher] Failed to publish ZeroTrust event - category={}, type={}, error: {}, duration={}ms",
                            event.getCategory(), event.getEventType(), ex.getMessage(), duration, ex);
                    sendToDeadLetterQueue(event, ex);
                }
            });

        } catch (Exception e) {
            log.error("[KafkaPublisher] Error publishing ZeroTrust event - category={}, type={}, error: {}",
                    event.getCategory(), event.getEventType(), e.getMessage(), e);
            sendToDeadLetterQueue(event, e);
        }
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

            kafkaTemplate.send(deadLetterTopic, dlqEvent);
            log.warn("Event sent to Dead Letter Queue: {}", event);
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
