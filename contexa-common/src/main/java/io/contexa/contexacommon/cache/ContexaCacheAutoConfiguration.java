/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacommon.cache;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.SimpleAsyncTaskExecutor;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.data.redis.listener.adapter.MessageListenerAdapter;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;


/**
 * The distributed cache service is made from the application's Redis (a StringRedisTemplate), so it is evaluated after Spring Boot's Redis
 * auto-configuration and Contexa's own; before that the template does not exist yet and the service would silently not be made.
 */
@AutoConfiguration(afterName = {
        "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration",
        "io.contexa.contexacommon.config.redis.CommonRedisAutoConfiguration"})
@EnableConfigurationProperties(ContexaCacheProperties.class)
@ConditionalOnProperty(name = "contexa.cache.enabled", havingValue = "true", matchIfMissing = true)
@Slf4j
public class ContexaCacheAutoConfiguration {

    @Configuration
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
    @ConditionalOnBean(StringRedisTemplate.class)
    static class DistributedCacheConfig {

        /**
         * The application's template is read only when Contexa's own is missing: resolved up front it was made for nothing, and a host
         * with lazy initialisation saw its {@code stringRedisTemplate} made by Contexa.
         */
        @Bean
        @ConditionalOnMissingBean(ContexaCacheService.class)
        public RedisContexaCacheService contexaCacheService(
                ContexaCacheProperties properties,
                ObjectProvider<StringRedisTemplate> redisTemplate,
                @Qualifier("contexaStringRedisTemplate") ObjectProvider<StringRedisTemplate> contexaStrings,
                @Qualifier("contexaObjectMapper") ObjectProvider<ObjectMapper> objectMapper) {
            return new RedisContexaCacheService(properties, contexaStrings.getIfAvailable(redisTemplate::getObject),
                    objectMapper.getIfAvailable(ContexaCacheAutoConfiguration::ownObjectMapper));
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
            // what the container makes itself when none is given (a SimpleAsyncTaskExecutor), with a name that says it is Contexa's
            container.setTaskExecutor(new SimpleAsyncTaskExecutor("contexa-cache-listener-"));

            if (properties.getPubsub().isEnabled()) {
                ChannelTopic topic = new ChannelTopic(properties.getPubsub().qualifiedChannel());
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
                @Qualifier("contexaObjectMapper") ObjectProvider<ObjectMapper> objectMapper) {
            return new LocalContexaCacheService(properties, objectMapper.getIfAvailable(ContexaCacheAutoConfiguration::ownObjectMapper));
        }
    }

    @Configuration
    @ConditionalOnMissingBean(ContexaCacheService.class)
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "standalone", matchIfMissing = true)
    static class FallbackCacheConfig {

        @Bean
        public LocalContexaCacheService contexaCacheService(
                ContexaCacheProperties properties,
                @Qualifier("contexaObjectMapper") ObjectProvider<ObjectMapper> objectMapper) {
            log.info("No ContexaCacheService bean found from distributed or standalone config. Falling back to local cache.");
            return new LocalContexaCacheService(properties, objectMapper.getIfAvailable(ContexaCacheAutoConfiguration::ownObjectMapper));
        }
    }

    /**
     * The mapper of the cache when Contexa's own is not in the context (this library is used without the Contexa core). It is never the
     * application's mapper: what the cache stores must not depend on how the application configured its JSON.
     */
    static ObjectMapper ownObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return mapper;
    }
}
