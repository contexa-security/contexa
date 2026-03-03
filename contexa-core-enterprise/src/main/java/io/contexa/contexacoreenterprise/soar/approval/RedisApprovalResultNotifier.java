package io.contexa.contexacoreenterprise.soar.approval;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;

@Slf4j
@RequiredArgsConstructor
public class RedisApprovalResultNotifier implements ApprovalResultNotifier {

    private final StringRedisTemplate redisTemplate;

    @Override
    public void publishResult(String approvalId, boolean approved) {
        try {
            String channel = "approval:" + approvalId;
            String message = approved ? "APPROVED" : "REJECTED";
            redisTemplate.convertAndSend(channel, message);
        } catch (Exception e) {
            log.error("[ApprovalResultNotifier] Redis Pub/Sub publish failed: {}", approvalId, e);
        }
    }
}
