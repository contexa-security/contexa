package io.contexa.autoconfigure.core.infra;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.config.*;
import io.contexa.contexacore.infra.kafka.KafkaConfiguration;
import io.contexa.contexacore.infra.redis.UnifiedRedisConfiguration;
import io.contexa.contexacore.security.async.AsyncSecurityContextProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.RedisTemplate;

@AutoConfiguration
@ConditionalOnProperty(prefix = "contexa", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({ ContexaProperties.class, io.contexa.contexacore.properties.OpenTelemetryProperties.class })
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
    @ConditionalOnProperty(prefix = "contexa.security.async", name = "enabled", havingValue = "true", matchIfMissing = true)
    public AsyncSecurityContextProvider asyncSecurityContextProvider(RedisTemplate<String, Object> redisTemplate) {
        return new AsyncSecurityContextProvider(redisTemplate);
    }
}
