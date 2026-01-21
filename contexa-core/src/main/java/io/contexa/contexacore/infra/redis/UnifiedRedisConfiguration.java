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

@Slf4j
@Configuration
public class UnifiedRedisConfiguration {

    public static final String SOAR_APPROVAL_CHANNEL = "soar:approval:requests";

    @Bean
    public RedisMessageListenerContainer redisMessageListenerContainer(
            RedisConnectionFactory connectionFactory,
            @Autowired(required = false) SoarApprovalNotifier soarApprovalNotifier,
            @Autowired RedisTemplate<String, Object> generalRedisTemplate
    ) {
        
        RedisMessageListenerContainer container = new RedisMessageListenerContainer();
        container.setConnectionFactory(connectionFactory);

        if (soarApprovalNotifier != null) {
                        MessageListenerAdapter listenerAdapter =
                new MessageListenerAdapter(soarApprovalNotifier, "receiveApprovalNotification");
            listenerAdapter.setSerializer(generalRedisTemplate.getValueSerializer());
            container.addMessageListener(listenerAdapter, new ChannelTopic(SOAR_APPROVAL_CHANNEL));
        } else {
                    }

        return container;
    }

    @Bean
    public RedisDistributedLockService redisDistributedLockService(
            @Autowired(required = false) RedisTemplate<String, Object> redisTemplate) {

        if (redisTemplate != null) {
                        return new RedisDistributedLockService(redisTemplate);
        }
        return null;
    }
}
