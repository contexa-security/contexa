package io.contexa.contexacore.infra.redis;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Redis 기반 이벤트 발행 서비스
 * 분산 환경에서 서버 간 이벤트 공유
 *
 * eventRedisTemplate을 사용하여 타입 정보 없이 깔끔한 JSON으로 직렬화합니다.
 */
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

    /**
     * 인증 이벤트 발행
     */
    public void publishAuthenticationEvent(String eventType, String username,
                                           Map<String, Object> additionalData) {
        Map<String, Object> event = createEvent("AUTHENTICATION", eventType, username, additionalData);
        publishEvent("authentication-events", event);
    }

    /**
     * MFA 이벤트 발행
     */
    public void publishMfaEvent(String eventType, String sessionId,
                                String username, Map<String, Object> additionalData) {
        Map<String, Object> data = new HashMap<>(additionalData);
        data.put("sessionId", sessionId);

        Map<String, Object> event = createEvent("MFA", eventType, username, data);
        publishEvent("mfa-events", event);
    }

    /**
     * 보안 이벤트 발행
     */
    public void publishSecurityEvent(String eventType, String username,
                                     String ipAddress, Map<String, Object> additionalData) {
        Map<String, Object> data = new HashMap<>(additionalData);
        data.put("ipAddress", ipAddress);

        Map<String, Object> event = createEvent("SECURITY", eventType, username, data);
        publishEvent("security-events", event);
    }

    /**
     * 이벤트 생성
     */
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

    /**
     * 이벤트 발행
     */
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

    /**
     * 서버 ID 가져오기
     */
    private String getServerId() {
        // 실제로는 서버 인스턴스 ID나 호스트명을 사용
        return System.getenv("HOSTNAME") != null ?
                System.getenv("HOSTNAME") : "server-" + System.currentTimeMillis();
    }
}
