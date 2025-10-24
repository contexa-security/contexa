package io.contexa.contexacore.config;

import org.redisson.Redisson;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.convert.DurationUnit;
import lombok.extern.slf4j.Slf4j;
import java.time.Duration;
import java.time.temporal.ChronoUnit;

/**
 * Redisson 설정 - 로컬 개발 환경용
 * Spring Boot의 자동 설정을 오버라이드하여 비밀번호 없이 연결
 */
@Slf4j
@Configuration
@ConditionalOnClass(Redisson.class)
public class RedissonConfiguration {

    @Value("${spring.data.redis.host:localhost}")
    private String redisHost;

    @Value("${spring.data.redis.port:6379}")
    private int redisPort;

    @Value("${spring.data.redis.timeout:5000ms}")
    @DurationUnit(ChronoUnit.MILLIS)
    private Duration timeout;

    @Bean
    @ConditionalOnMissingBean(RedissonClient.class)
    public RedissonClient redissonClient() {
        Config config = new Config();

        // 단일 서버 설정 (로컬 개발용)
        String address = String.format("redis://%s:%d", redisHost, redisPort);
        config.useSingleServer()
            .setAddress(address)
            .setPassword(null)  // 비밀번호 명시적으로 null 설정
            .setDatabase(0)
            .setConnectionMinimumIdleSize(2)
            .setConnectionPoolSize(10)
            .setIdleConnectionTimeout(10000)
            .setConnectTimeout((int) timeout.toMillis())
            .setTimeout(3000)
            .setRetryAttempts(3)
            .setRetryInterval(1500)
            .setPingConnectionInterval(0);

        log.info("Creating RedissonClient with address: {} (no password)", address);

        return Redisson.create(config);
    }
}