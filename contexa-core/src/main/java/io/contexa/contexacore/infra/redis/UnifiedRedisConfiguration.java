package io.contexa.contexacore.infra.redis;

import io.contexa.contexacore.autonomous.notification.SoarApprovalNotifier;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.data.redis.listener.adapter.MessageListenerAdapter;

/**
 * contexa-core 전용 Redis 설정
 *
 * 공통 빈은 contexa-common의 CommonRedisConfiguration에서 제공
 *
 * 제공 빈:
 * - RedisMessageListenerContainer: SOAR 승인 알림 리스너
 * - RedisDistributedLockService: 분산 락 서비스
 */
@Slf4j
@Configuration
public class UnifiedRedisConfiguration {

    // SOAR 승인 요청 알림 채널 이름
    public static final String SOAR_APPROVAL_CHANNEL = "soar:approval:requests";

    /**
     * Redis 메시지 리스너 컨테이너
     * Enterprise의 SoarApprovalNotifier가 있으면 자동으로 등록
     */
    @Bean
    public RedisMessageListenerContainer redisMessageListenerContainer(
            RedisConnectionFactory connectionFactory,
            @Autowired(required = false) SoarApprovalNotifier soarApprovalNotifier,
            @Autowired RedisTemplate<String, Object> generalRedisTemplate
    ) {
        log.info("Creating Redis message listener container");

        RedisMessageListenerContainer container = new RedisMessageListenerContainer();
        container.setConnectionFactory(connectionFactory);

        // SoarApprovalNotifier가 있으면 리스너로 등록
        if (soarApprovalNotifier != null) {
            log.info("Registering SOAR approval notifier to Redis message listener");
            MessageListenerAdapter listenerAdapter =
                new MessageListenerAdapter(soarApprovalNotifier, "receiveApprovalNotification");
            listenerAdapter.setSerializer(generalRedisTemplate.getValueSerializer());
            container.addMessageListener(listenerAdapter, new ChannelTopic(SOAR_APPROVAL_CHANNEL));
        } else {
            log.debug("SOAR approval notifier not available");
        }

        return container;
    }

    /**
     * Redis 분산 락 서비스
     */
    @Bean
    public RedisDistributedLockService redisDistributedLockService(
            @Autowired(required = false) RedisTemplate<String, Object> redisTemplate) {

        if (redisTemplate != null) {
            log.info("Creating RedisDistributedLockService");
            return new RedisDistributedLockService(redisTemplate);
        }
        return null;
    }
}
