package io.contexa.contexacore.infra.redis;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.connection.Message;
import org.springframework.data.redis.connection.MessageListener;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;
import java.util.Map;


@Slf4j
@RequiredArgsConstructor
public class RedisEventListener implements MessageListener {

    private final RedisMessageListenerContainer messageListenerContainer;
    private final ObjectMapper objectMapper;

    private static final List<String> TOPICS = Arrays.asList(
            "authentication-events",
            "mfa-events",
            "security-events"
    );

    @PostConstruct
    public void init() {
        
        TOPICS.forEach(topic -> {
            messageListenerContainer.addMessageListener(this, new ChannelTopic(topic));
            log.info("Subscribed to Redis topic: {}", topic);
        });
    }

    @Override
    public void onMessage(Message message, byte[] pattern) {
        try {
            String channel = new String(message.getChannel());
            String eventJson = new String(message.getBody());

            

        } catch (Exception e) {
            log.error("Failed to process Redis message: {}", e.getMessage());
        }
    }

    
    private void processEvent(String channel, Map<String, Object> event) {
        String category = (String) event.get("category");
        String eventType = (String) event.get("eventType");
        String username = (String) event.get("username");
        Map<String, Object> data = (Map<String, Object>) event.get("data");

        switch (category) {
            case "AUTHENTICATION":
                handleAuthenticationEvent(eventType, username, data);
                break;
            case "MFA":
                handleMfaEvent(eventType, username, data);
                break;
            case "SECURITY":
                handleSecurityEvent(eventType, username, data);
                break;
            default:
                log.warn("Unknown event category: {}", category);
        }
    }

    
    private void handleAuthenticationEvent(String eventType, String username,
                                           Map<String, Object> data) {
        log.info("Authentication event - Type: {}, User: {}", eventType, username);

        
        if ("LOGIN_SUCCESS".equals(eventType)) {
            
        }
    }

    
    private void handleMfaEvent(String eventType, String username,
                                Map<String, Object> data) {
        String sessionId = (String) data.get("sessionId");
        log.info("MFA event - Type: {}, User: {}, Session: {}", eventType, username, sessionId);

        
    }

    
    private void handleSecurityEvent(String eventType, String username,
                                     Map<String, Object> data) {
        String ipAddress = (String) data.get("ipAddress");
        log.info("Security event - Type: {}, User: {}, IP: {}", eventType, username, ipAddress);

        
    }
}
