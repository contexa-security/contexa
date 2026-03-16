package io.contexa.contexacore.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.redisson.Redisson;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Slf4j
@Configuration
@RequiredArgsConstructor
@ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
public class RedissonConfiguration {

    private final RedisProperties redisProperties;

    @Bean
    @ConditionalOnMissingBean(RedissonClient.class)
    public RedissonClient redissonClient() {
        Config config = new Config();

        String address = String.format("redis://%s:%d", redisProperties.getHost(), redisProperties.getPort());
        java.time.Duration timeout = redisProperties.getTimeout() != null ? redisProperties.getTimeout() : java.time.Duration.ofMillis(5000);
        config.useSingleServer()
            .setAddress(address)
            .setPassword(null)
            .setDatabase(0)
            .setConnectionMinimumIdleSize(2)
            .setConnectionPoolSize(10)
            .setIdleConnectionTimeout(10000)
            .setConnectTimeout((int) timeout.toMillis())
            .setTimeout(3000)
            .setRetryAttempts(3)
            .setPingConnectionInterval(0);

        return Redisson.create(config);
    }
}