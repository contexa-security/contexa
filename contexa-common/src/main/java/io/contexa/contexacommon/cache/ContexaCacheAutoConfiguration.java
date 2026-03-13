package io.contexa.contexacommon.cache;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.data.redis.listener.adapter.MessageListenerAdapter;


@AutoConfiguration
@EnableConfigurationProperties(ContexaCacheProperties.class)
@ConditionalOnProperty(name = "contexa.cache.enabled", havingValue = "true", matchIfMissing = true)
@Slf4j
public class ContexaCacheAutoConfiguration {

    @Configuration
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
    @ConditionalOnBean(StringRedisTemplate.class)
    static class DistributedCacheConfig {

        @Bean
        @ConditionalOnMissingBean(ContexaCacheService.class)
        public RedisContexaCacheService contexaCacheService(
                ContexaCacheProperties properties,
                StringRedisTemplate redisTemplate,
                ObjectMapper objectMapper) {
            return new RedisContexaCacheService(properties, redisTemplate, objectMapper);
        }

        @Bean
        @ConditionalOnMissingBean
        @ConditionalOnProperty(name = "contexa.cache.type", havingValue = "HYBRID")
        public ContexaCacheInvalidationListener contexaCacheInvalidationListener(
                ContexaCacheService cacheService,
                ContexaCacheProperties properties) {
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

    @Configuration
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "standalone", matchIfMissing = true)
    static class StandaloneCacheConfig {

        @Bean
        @ConditionalOnMissingBean(ContexaCacheService.class)
        public LocalContexaCacheService contexaCacheService(
                ContexaCacheProperties properties,
                ObjectMapper objectMapper) {
            return new LocalContexaCacheService(properties, objectMapper);
        }
    }

    @Configuration
    @ConditionalOnMissingBean(ContexaCacheService.class)
    static class FallbackCacheConfig {

        @Bean
        public LocalContexaCacheService contexaCacheService(
                ContexaCacheProperties properties,
                ObjectMapper objectMapper) {
            log.error("No ContexaCacheService bean found from distributed or standalone config. Falling back to local cache.");
            return new LocalContexaCacheService(properties, objectMapper);
        }
    }
}
