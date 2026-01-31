package io.contexa.autoconfigure.core.infra;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.config.ApplicationConfig;
import io.contexa.contexacore.config.AsyncConfig;
import io.contexa.contexacore.config.KafkaTopicConfiguration;
import io.contexa.contexacore.config.OpenTelemetryConfiguration;
import io.contexa.contexacore.config.RedisKeyCleanup;
import io.contexa.contexacore.config.RedissonConfiguration;
import io.contexa.contexacore.infra.kafka.KafkaConfiguration;
import io.contexa.contexacore.infra.redis.UnifiedRedisConfiguration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.RedisTemplate;

@AutoConfiguration
@ConditionalOnProperty(prefix = "contexa", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(ContexaProperties.class)
@Import({
        ApplicationConfig.class,
        AsyncConfig.class,
        UnifiedRedisConfiguration.class,
        RedissonConfiguration.class,
        KafkaConfiguration.class,
        KafkaTopicConfiguration.class,
        OpenTelemetryConfiguration.class
})
public class CoreInfrastructureAutoConfiguration {

    public CoreInfrastructureAutoConfiguration() {
    }

    @Bean
    @ConditionalOnMissingBean
    public RedisKeyCleanup redisKeyCleanup(RedisTemplate<String, Object> redisTemplate) {
        return new RedisKeyCleanup(redisTemplate);
    }
}
