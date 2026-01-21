package io.contexa.contexacoreenterprise.soar.event;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacoreenterprise.soar.approval.UnifiedApprovalService;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.connection.Message;
import org.springframework.data.redis.connection.MessageListener;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@ConditionalOnProperty(name = "spring.redis.enabled", havingValue = "true", matchIfMissing = true)
public class RedisApprovalSubscriber implements MessageListener {
    
    @Autowired
    private RedisMessageListenerContainer messageListenerContainer;
    
    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UnifiedApprovalService unifiedApprovalService;

    private final Set<String> subscribedChannels = ConcurrentHashMap.newKeySet();

    private static final String CHANNEL_PREFIX = "approval:";
    private static final String BROADCAST_CHANNEL = "approval:broadcast";
    
    @PostConstruct
    public void init() {
        
        subscribeToChannel(BROADCAST_CHANNEL);
            }

    @Override
    public void onMessage(Message message, byte[] pattern) {
        try {
            String channel = new String(message.getChannel());
            String body = new String(message.getBody());

            if (channel.startsWith(CHANNEL_PREFIX)) {
                handleApprovalMessage(channel, body);
            }
            
        } catch (Exception e) {
            log.error("Redis 메시지 처리 실패", e);
        }
    }

    private void handleApprovalMessage(String channel, String messageBody) {
        
        String approvalId = extractApprovalId(channel);
        if (approvalId == null) {
            log.warn("승인 ID를 추출할 수 없음: {}", channel);
            return;
        }

        switch (messageBody) {
            case "APPROVED" -> handleApprovalGranted(approvalId);
            case "REJECTED" -> handleApprovalDenied(approvalId);
            case "CANCELLED" -> handleApprovalCancelled(approvalId);
            case "TIMEOUT" -> handleApprovalTimeout(approvalId);
            default -> handleJsonMessage(approvalId, messageBody);
        }
    }

    private void handleApprovalGranted(String approvalId) {
                
        unifiedApprovalService.processApprovalResponse(approvalId, true, "REDIS_USER", "Approved via Redis");
    }

    private void handleApprovalDenied(String approvalId) {
                
        unifiedApprovalService.processApprovalResponse(approvalId, false, "REDIS_USER", "Denied via Redis");
    }

    private void handleApprovalCancelled(String approvalId) {
                unifiedApprovalService.cancelApproval(approvalId, "Cancelled via Redis");
    }

    private void handleApprovalTimeout(String approvalId) {
        log.warn("Redis: 승인 타임아웃 수신 - {}", approvalId);
        unifiedApprovalService.processApprovalResponse(approvalId, false, "SYSTEM", "Timeout via Redis");
    }

    private void handleJsonMessage(String approvalId, String json) {
        try {
            Map<String, Object> data = objectMapper.readValue(json, Map.class);
            
            String type = (String) data.get("type");
            if (type == null) {
                log.warn("메시지 타입이 없음: {}", json);
                return;
            }
            
            switch (type) {
                case "APPROVAL_RESPONSE" -> {
                    boolean approved = (boolean) data.getOrDefault("approved", false);
                    String reviewer = (String) data.getOrDefault("reviewer", "UNKNOWN");
                    String comment = (String) data.getOrDefault("comment", "");
                    
                    unifiedApprovalService.processApprovalResponse(approvalId, approved, reviewer, comment);
                }
                case "APPROVAL_CANCEL" -> {
                    String reason = (String) data.getOrDefault("reason", "Cancelled");
                    unifiedApprovalService.cancelApproval(approvalId, reason);
                }
                default -> log.debug("알 수 없는 메시지 타입: {}", type);
            }
            
        } catch (Exception e) {
            log.error("JSON 메시지 파싱 실패: {}", json, e);
        }
    }

    public void subscribeToApproval(String approvalId) {
        String channel = CHANNEL_PREFIX + approvalId;
        subscribeToChannel(channel);
    }

    public void unsubscribeFromApproval(String approvalId) {
        String channel = CHANNEL_PREFIX + approvalId;
        unsubscribeFromChannel(channel);
    }

    private void subscribeToChannel(String channel) {
        if (subscribedChannels.contains(channel)) {
                        return;
        }
        
        messageListenerContainer.addMessageListener(this, new ChannelTopic(channel));
        subscribedChannels.add(channel);
        
            }

    private void unsubscribeFromChannel(String channel) {
        if (!subscribedChannels.contains(channel)) {
            return;
        }

        subscribedChannels.remove(channel);
        
            }

    private String extractApprovalId(String channel) {
        if (channel.startsWith(CHANNEL_PREFIX)) {
            return channel.substring(CHANNEL_PREFIX.length());
        }
        return null;
    }

    public void unsubscribeAll() {
        subscribedChannels.clear();
            }

    public int getSubscribedChannelCount() {
        return subscribedChannels.size();
    }

    public boolean isSubscribed(String channel) {
        return subscribedChannels.contains(channel);
    }
}