package io.contexa.autoconfigure.core.infrastructure;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.config.ApplicationConfig;
import io.contexa.contexacore.config.AsyncConfig;
import io.contexa.contexacore.config.KafkaTopicConfiguration;
import io.contexa.contexacore.config.OpenTelemetryConfiguration;
import io.contexa.contexacore.config.RedisKeyCleanup;
import io.contexa.contexacore.config.RedissonConfiguration;
import io.contexa.contexacore.infra.kafka.KafkaConfiguration;
import io.contexa.contexacore.infra.redis.DistributedAIStrategyCoordinator;
import io.contexa.contexacore.infra.redis.RedisAsyncEventConfiguration;
import io.contexa.contexacore.infra.redis.RedisCacheConfiguration;
import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import io.contexa.contexacore.infra.redis.RedisEventPublisher;
import io.contexa.contexacore.infra.redis.UnifiedRedisConfiguration;
import io.contexa.contexacore.scheduler.VirtualThreadConfiguration;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.RedisTemplate;

/**
 * Core Infrastructure AutoConfiguration
 *
 * <p>
 * Contexa 프레임워크의 Infrastructure 관련 자동 구성을 제공합니다.
 * Import 방식으로 기존 Configuration 클래스들을 재사용합니다.
 * </p>
 *
 * <h3>포함된 Configuration:</h3>
 * <ul>
 *   <li>ApplicationConfig - ObjectMapper, ModelMapper</li>
 *   <li>AsyncConfig - @EnableAsync 설정</li>
 *   <li>VirtualThreadConfiguration - 가상 스레드</li>
 *   <li>UnifiedRedisConfiguration - Redis 통합 설정 (조건부)</li>
 *   <li>RedisAsyncEventConfiguration - Redis 비동기 이벤트 (조건부)</li>
 *   <li>RedisCacheConfiguration - Redis 캐시 (조건부)</li>
 *   <li>RedissonConfiguration - Redisson (조건부)</li>
 *   <li>KafkaConfiguration - Kafka 기본 설정 (조건부)</li>
 *   <li>KafkaTopicConfiguration - Kafka 토픽 (조건부)</li>
 *   <li>OpenTelemetryConfiguration - 관찰성 (조건부)</li>
 * </ul>
 *
 * <h3>활성화 조건:</h3>
 * <pre>
 * contexa:
 *   enabled: true  # (기본값)
 * </pre>
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@ConditionalOnProperty(
    prefix = "contexa",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
@EnableConfigurationProperties(ContexaProperties.class)
@Import({
    ApplicationConfig.class,
    AsyncConfig.class,
    VirtualThreadConfiguration.class,
    UnifiedRedisConfiguration.class,
    RedisAsyncEventConfiguration.class,
    RedisCacheConfiguration.class,
    RedissonConfiguration.class,
    KafkaConfiguration.class,
    KafkaTopicConfiguration.class,
    OpenTelemetryConfiguration.class
})
public class CoreInfrastructureAutoConfiguration {

    /**
     * Constructor
     *
     * <p>
     * Import된 Configuration 클래스들이 자동으로 등록됩니다.
     * 각 Configuration은 자체적으로 @Conditional 조건을 가질 수 있습니다.
     * </p>
     */
    public CoreInfrastructureAutoConfiguration() {
        // Import만 수행, 추가 Bean 등록은 여기서
    }

    // ========== Infrastructure Components ==========

    @Bean
    @ConditionalOnMissingBean
    public RedisKeyCleanup redisKeyCleanup(RedisTemplate<String, Object> redisTemplate) {
        return new RedisKeyCleanup(redisTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    public RedisEventPublisher redisEventPublisher(
            @Qualifier("eventRedisTemplate") RedisTemplate<String, Object> redisTemplate,
            ObjectMapper objectMapper) {
        return new RedisEventPublisher(redisTemplate, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public DistributedAIStrategyCoordinator distributedAIStrategyCoordinator(
            RedisTemplate<String, Object> redisTemplate,
            RedisDistributedLockService lockService,
            RedisEventPublisher eventPublisher) {
        return new DistributedAIStrategyCoordinator(redisTemplate, lockService, eventPublisher);
    }
}
