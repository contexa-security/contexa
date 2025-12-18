package io.contexa.contexacommon.cache;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.data.redis.listener.adapter.MessageListenerAdapter;

/**
 * Contexa 캐시 자동 설정
 *
 * 2-Level 캐시 시스템을 자동으로 구성합니다:
 * - L1: Caffeine (로컬 인메모리)
 * - L2: Redis (분산)
 * - Pub/Sub: 분산 노드 간 캐시 무효화
 *
 * 활성화 조건:
 * - contexa.cache.enabled=true (기본값)
 * - StringRedisTemplate 빈 존재
 * - ObjectMapper 빈 존재
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@EnableConfigurationProperties(ContexaCacheProperties.class)
@ConditionalOnProperty(name = "contexa.cache.enabled", havingValue = "true", matchIfMissing = true)
@ConditionalOnClass({StringRedisTemplate.class, ObjectMapper.class})
@Slf4j
public class ContexaCacheAutoConfiguration {

    /**
     * ContexaCacheService 빈 등록
     *
     * @param properties 캐시 설정
     * @param redisTemplate Redis 템플릿
     * @param objectMapper JSON 직렬화/역직렬화
     * @return ContexaCacheService 인스턴스
     */
    @Bean
    @ConditionalOnMissingBean
    public ContexaCacheService contexaCacheService(
            ContexaCacheProperties properties,
            StringRedisTemplate redisTemplate,
            ObjectMapper objectMapper) {

        log.info("ContexaCacheService 빈 등록 - type: {}, L1 maxSize: {}, L2 TTL: {}s",
            properties.getType(),
            properties.getLocal().getMaxSize(),
            properties.getRedis().getDefaultTtlSeconds());

        return new ContexaCacheService(properties, redisTemplate, objectMapper);
    }

    /**
     * 캐시 무효화 리스너 빈 등록
     *
     * HYBRID 모드에서 Pub/Sub 활성화 시에만 등록
     *
     * @param cacheService 캐시 서비스
     * @return 무효화 리스너 인스턴스
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(name = "contexa.cache.type", havingValue = "HYBRID")
    public ContexaCacheInvalidationListener contexaCacheInvalidationListener(
            ContexaCacheService cacheService,
            ContexaCacheProperties properties) {

        log.info("ContexaCacheInvalidationListener 빈 등록 - channel: {}",
            properties.getPubsub().getChannel());

        return new ContexaCacheInvalidationListener(cacheService, properties);
    }

    /**
     * Redis Pub/Sub 메시지 리스너 컨테이너 빈 등록
     *
     * HYBRID 모드에서 Pub/Sub 활성화 시에만 등록
     *
     * @param connectionFactory Redis 연결 팩토리
     * @param listenerAdapter 메시지 리스너 어댑터
     * @param properties 캐시 설정
     * @return 리스너 컨테이너
     */
    @Bean
    @ConditionalOnMissingBean(name = "contexaCacheListenerContainer")
    @ConditionalOnProperty(name = "contexa.cache.type", havingValue = "HYBRID")
    public RedisMessageListenerContainer contexaCacheListenerContainer(
            RedisConnectionFactory connectionFactory,
            MessageListenerAdapter contexaCacheListenerAdapter,
            ContexaCacheProperties properties) {

        RedisMessageListenerContainer container = new RedisMessageListenerContainer();
        container.setConnectionFactory(connectionFactory);

        if (properties.getPubsub().isEnabled()) {
            ChannelTopic topic = new ChannelTopic(properties.getPubsub().getChannel());
            container.addMessageListener(contexaCacheListenerAdapter, topic);
            log.info("Redis Pub/Sub 리스너 컨테이너 등록 - channel: {}", properties.getPubsub().getChannel());
        }

        return container;
    }

    /**
     * 메시지 리스너 어댑터 빈 등록
     *
     * @param listener 무효화 리스너
     * @return 메시지 리스너 어댑터
     */
    @Bean
    @ConditionalOnMissingBean(name = "contexaCacheListenerAdapter")
    @ConditionalOnProperty(name = "contexa.cache.type", havingValue = "HYBRID")
    public MessageListenerAdapter contexaCacheListenerAdapter(
            ContexaCacheInvalidationListener listener) {

        return new MessageListenerAdapter(listener, "handleMessage");
    }
}
