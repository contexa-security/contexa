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


@AutoConfiguration
@EnableConfigurationProperties(ContexaCacheProperties.class)
@ConditionalOnProperty(name = "contexa.cache.enabled", havingValue = "true", matchIfMissing = true)
@ConditionalOnClass({StringRedisTemplate.class, ObjectMapper.class})
@Slf4j
public class ContexaCacheAutoConfiguration {

    
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

    
    @Bean
    @ConditionalOnMissingBean(name = "contexaCacheListenerAdapter")
    @ConditionalOnProperty(name = "contexa.cache.type", havingValue = "HYBRID")
    public MessageListenerAdapter contexaCacheListenerAdapter(
            ContexaCacheInvalidationListener listener) {

        return new MessageListenerAdapter(listener, "handleMessage");
    }
}
