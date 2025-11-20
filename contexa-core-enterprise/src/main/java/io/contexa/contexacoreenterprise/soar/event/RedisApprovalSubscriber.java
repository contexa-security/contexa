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
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Redis 승인 구독자
 * 
 * Redis Pub/Sub 메시지를 수신하여 승인 이벤트를 처리합니다.
 * 폴링 없이 실시간으로 메시지를 수신합니다.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "spring.redis.enabled", havingValue = "true", matchIfMissing = true)
public class RedisApprovalSubscriber implements MessageListener {
    
    @Autowired
    private RedisMessageListenerContainer messageListenerContainer;
    
    @Autowired
    private ObjectMapper objectMapper;
    
    // UnifiedApprovalService 주입
    @Autowired
    private UnifiedApprovalService unifiedApprovalService;
    
    // 구독 중인 채널 관리
    private final Set<String> subscribedChannels = ConcurrentHashMap.newKeySet();
    
    // 채널 패턴
    private static final String CHANNEL_PREFIX = "approval:";
    private static final String BROADCAST_CHANNEL = "approval:broadcast";
    
    @PostConstruct
    public void init() {
        // 브로드캐스트 채널 구독
        subscribeToChannel(BROADCAST_CHANNEL);
        log.info("Redis 승인 구독자 초기화 완료");
    }
    
    /**
     * Redis 메시지 수신 처리
     */
    @Override
    public void onMessage(Message message, byte[] pattern) {
        try {
            String channel = new String(message.getChannel());
            String body = new String(message.getBody());
            
            log.debug("Redis 메시지 수신: {} -> {}", channel, body);
            
            // 채널별 메시지 처리
            if (channel.startsWith(CHANNEL_PREFIX)) {
                handleApprovalMessage(channel, body);
            }
            
        } catch (Exception e) {
            log.error("Redis 메시지 처리 실패", e);
        }
    }
    
    /**
     * 승인 메시지 처리
     */
    private void handleApprovalMessage(String channel, String messageBody) {
        // 채널에서 승인 ID 추출
        String approvalId = extractApprovalId(channel);
        if (approvalId == null) {
            log.warn("승인 ID를 추출할 수 없음: {}", channel);
            return;
        }
        
        // 메시지 타입별 처리
        switch (messageBody) {
            case "APPROVED" -> handleApprovalGranted(approvalId);
            case "REJECTED" -> handleApprovalDenied(approvalId);
            case "CANCELLED" -> handleApprovalCancelled(approvalId);
            case "TIMEOUT" -> handleApprovalTimeout(approvalId);
            default -> handleJsonMessage(approvalId, messageBody);
        }
    }
    
    /**
     * 승인 허가 처리
     */
    private void handleApprovalGranted(String approvalId) {
        log.info("Redis: 승인 허가 수신 - {}", approvalId);
        
        unifiedApprovalService.processApprovalResponse(approvalId, true, "REDIS_USER", "Approved via Redis");
    }
    
    /**
     * 승인 거부 처리
     */
    private void handleApprovalDenied(String approvalId) {
        log.info("Redis: 승인 거부 수신 - {}", approvalId);
        
        unifiedApprovalService.processApprovalResponse(approvalId, false, "REDIS_USER", "Denied via Redis");
    }
    
    /**
     * 승인 취소 처리
     */
    private void handleApprovalCancelled(String approvalId) {
        log.info("🚫 Redis: 승인 취소 수신 - {}", approvalId);
        unifiedApprovalService.cancelApproval(approvalId, "Cancelled via Redis");
    }
    
    /**
     * 승인 타임아웃 처리
     */
    private void handleApprovalTimeout(String approvalId) {
        log.warn("Redis: 승인 타임아웃 수신 - {}", approvalId);
        unifiedApprovalService.processApprovalResponse(approvalId, false, "SYSTEM", "Timeout via Redis");
    }
    
    /**
     * JSON 메시지 처리
     */
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
    
    /**
     * 특정 승인 ID 채널 구독
     * 
     * @param approvalId 승인 ID
     */
    public void subscribeToApproval(String approvalId) {
        String channel = CHANNEL_PREFIX + approvalId;
        subscribeToChannel(channel);
    }
    
    /**
     * 특정 승인 ID 채널 구독 해제
     * 
     * @param approvalId 승인 ID
     */
    public void unsubscribeFromApproval(String approvalId) {
        String channel = CHANNEL_PREFIX + approvalId;
        unsubscribeFromChannel(channel);
    }
    
    /**
     * 채널 구독
     */
    private void subscribeToChannel(String channel) {
        if (subscribedChannels.contains(channel)) {
            log.debug("이미 구독 중: {}", channel);
            return;
        }
        
        messageListenerContainer.addMessageListener(this, new ChannelTopic(channel));
        subscribedChannels.add(channel);
        
        log.info("Redis 채널 구독: {}", channel);
    }
    
    /**
     * 채널 구독 해제
     */
    private void unsubscribeFromChannel(String channel) {
        if (!subscribedChannels.contains(channel)) {
            return;
        }
        
        // 구독 해제 (실제 구현은 RedisMessageListenerContainer API에 따라 다를 수 있음)
        subscribedChannels.remove(channel);
        
        log.info("📴 Redis 채널 구독 해제: {}", channel);
    }
    
    /**
     * 채널에서 승인 ID 추출
     */
    private String extractApprovalId(String channel) {
        if (channel.startsWith(CHANNEL_PREFIX)) {
            return channel.substring(CHANNEL_PREFIX.length());
        }
        return null;
    }
    
    /**
     * 모든 구독 해제
     */
    public void unsubscribeAll() {
        subscribedChannels.clear();
        log.info("📴 모든 Redis 채널 구독 해제");
    }
    
    /**
     * 구독 중인 채널 수 조회
     */
    public int getSubscribedChannelCount() {
        return subscribedChannels.size();
    }
    
    /**
     * 특정 채널 구독 여부 확인
     */
    public boolean isSubscribed(String channel) {
        return subscribedChannels.contains(channel);
    }
}