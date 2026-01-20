package io.contexa.contexacore.infra.redis;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;


@Slf4j
public class RedisEventPublisher {

    private final RedisTemplate<String, Object> redisTemplate;
    private final ObjectMapper objectMapper;

    public RedisEventPublisher(
            @Qualifier("eventRedisTemplate") RedisTemplate<String, Object> redisTemplate,
            ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
    }

    
    public void publishAuthenticationEvent(String eventType, String username,
                                           Map<String, Object> additionalData) {
        Map<String, Object> event = createEvent("AUTHENTICATION", eventType, username, additionalData);
        publishEvent("authentication-events", event);
    }

    
    public void publishMfaEvent(String eventType, String sessionId,
                                String username, Map<String, Object> additionalData) {
        Map<String, Object> data = new HashMap<>(additionalData);
        data.put("sessionId", sessionId);

        Map<String, Object> event = createEvent("MFA", eventType, username, data);
        publishEvent("mfa-events", event);
    }

    
    public void publishSecurityEvent(String eventType, String username,
                                     String ipAddress, Map<String, Object> additionalData) {
        Map<String, Object> data = new HashMap<>(additionalData);
        data.put("ipAddress", ipAddress);

        Map<String, Object> event = createEvent("SECURITY", eventType, username, data);
        publishEvent("security-events", event);
    }

    
    private Map<String, Object> createEvent(String category, String eventType,
                                            String username, Map<String, Object> data) {
        Map<String, Object> event = new HashMap<>();
        event.put("category", category);
        event.put("eventType", eventType);
        event.put("username", username);
        event.put("timestamp", LocalDateTime.now().toString());
        event.put("serverId", getServerId());
        event.put("data", data);

        return event;
    }

    
    public void publishEvent(String topicName, Map<String, Object> event) {
        try {
            ChannelTopic topic = new ChannelTopic(topicName);
            String eventJson = objectMapper.writeValueAsString(event);

            redisTemplate.convertAndSend(topic.getTopic(), eventJson);

            log.debug("Event published to topic '{}': {}", topicName, event.get("eventType"));
        } catch (Exception e) {
            log.error("Failed to publish event to topic '{}': {}", topicName, e.getMessage());
        }
    }

    
    private String getServerId() {
        
        return System.getenv("HOSTNAME") != null ?
                System.getenv("HOSTNAME") : "server-" + System.currentTimeMillis();
    }
}
