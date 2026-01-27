package io.contexa.autoconfigure.core.infra;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.infra.redis.RedisAtomicOperations;
import io.contexa.contexacore.infra.redis.RedisEventListener;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;

@AutoConfiguration
@ConditionalOnProperty(prefix = "contexa.infrastructure", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(ContexaProperties.class)
public class CoreInfrastructureExtendedAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public RedisAtomicOperations redisAtomicOperations(RedisTemplate<String, Object> redisTemplate) {
        return new RedisAtomicOperations(redisTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    public RedisEventListener redisEventListener(
            RedisMessageListenerContainer messageListenerContainer,
            ObjectMapper objectMapper) {
        return new RedisEventListener(messageListenerContainer, objectMapper);
    }
}
