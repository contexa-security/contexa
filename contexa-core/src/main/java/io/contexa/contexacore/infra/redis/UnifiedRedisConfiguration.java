package io.contexa.contexacore.infra.redis;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
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
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Slf4j
@Configuration
public class UnifiedRedisConfiguration {

    public static final String SOAR_APPROVAL_CHANNEL = "soar:approval:requests";

    @Bean
    public RedisTemplate<String, SecurityEvent> securityEventRedisTemplate(
            RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, SecurityEvent> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        ObjectMapper objectMapper = createObjectMapper();
        GenericJackson2JsonRedisSerializer serializer =
                new GenericJackson2JsonRedisSerializer(objectMapper);

        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(serializer);
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setHashValueSerializer(serializer);

        template.afterPropertiesSet();
        return template;
    }

    private ObjectMapper createObjectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();

        objectMapper.registerModule(new JavaTimeModule());

        objectMapper.activateDefaultTyping(
                BasicPolymorphicTypeValidator.builder()
                        .allowIfSubType(Object.class)
                        .build(),
                ObjectMapper.DefaultTyping.NON_FINAL,
                JsonTypeInfo.As.PROPERTY
        );

        return objectMapper;
    }

    @Bean
    public RedisMessageListenerContainer redisMessageListenerContainer(
            RedisConnectionFactory connectionFactory,
            @Autowired(required = false) SoarApprovalNotifier soarApprovalNotifier,
            @Autowired RedisTemplate<String, Object> generalRedisTemplate) {

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
