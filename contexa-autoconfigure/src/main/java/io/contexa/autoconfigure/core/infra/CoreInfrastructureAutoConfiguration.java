package io.contexa.autoconfigure.core.infra;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.config.*;
import io.contexa.contexacore.infra.kafka.KafkaConfiguration;
import io.contexa.contexacore.infra.redis.UnifiedRedisConfiguration;
import io.contexa.contexacore.security.async.InMemoryAsyncSecurityContextProvider;
import io.contexa.contexacore.security.async.RedisAsyncSecurityContextProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.RedisTemplate;

import org.redisson.api.RedissonClient;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.kafka.core.KafkaTemplate;

@AutoConfiguration
@AutoConfigureAfter(name = {
        "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration",
        "io.contexa.contexacommon.config.redis.CommonRedisAutoConfiguration"
})
@ConditionalOnProperty(prefix = "contexa", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({ ContexaProperties.class, io.contexa.contexacore.properties.OpenTelemetryProperties.class })
@Import({
        ApplicationConfig.class,
        AsyncConfig.class,
        OpenTelemetryConfiguration.class
})
public class CoreInfrastructureAutoConfiguration {

    public CoreInfrastructureAutoConfiguration() {
    }


    @Configuration
    @ConditionalOnClass(name = "org.redisson.api.RedissonClient")
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
    @Import({
            UnifiedRedisConfiguration.class,
            RedissonConfiguration.class
    })
    static class DistributedRedisInfraConfiguration {
    }

    @Configuration
    @ConditionalOnClass(name = "org.springframework.kafka.core.KafkaTemplate")
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
    @Import({
            KafkaConfiguration.class,
            KafkaTopicConfiguration.class
    })
    static class DistributedKafkaInfraConfiguration {
    }

    @Configuration
    @ConditionalOnClass(name = "org.springframework.data.redis.core.RedisTemplate")
    @ConditionalOnBean(name = "generalRedisTemplate")
    @ConditionalOnProperty(prefix = "contexa.security.async", name = "enabled", havingValue = "true", matchIfMissing = true)
    static class RedisAsyncConfiguration {

        @Bean
        @ConditionalOnMissingBean
        public RedisAsyncSecurityContextProvider asyncSecurityContextProvider(
                @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate) {
            return new RedisAsyncSecurityContextProvider(redisTemplate);
        }
    }


    @Configuration
    @ConditionalOnMissingBean(name = "generalRedisTemplate")
    static class StandaloneAsyncConfiguration {

        @Bean
        @ConditionalOnMissingBean
        @ConditionalOnProperty(prefix = "contexa.security.async", name = "enabled", havingValue = "true", matchIfMissing = true)
        public InMemoryAsyncSecurityContextProvider inMemoryAsyncSecurityContextProvider() {
            return new InMemoryAsyncSecurityContextProvider();
        }
    }
}
