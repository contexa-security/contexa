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
package io.contexa.contexaidentity.config;

import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.lettuce.core.ClientOptions;
import io.lettuce.core.SocketOptions;
import io.lettuce.core.TimeoutOptions;
import io.lettuce.core.metrics.CommandLatencyRecorder;
import io.lettuce.core.resource.ClientResources;
import io.lettuce.core.resource.DefaultClientResources;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettucePoolingClientConfiguration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.time.Duration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@AutoConfiguration(before = RedisAutoConfiguration.class)
@RequiredArgsConstructor
@EnableConfigurationProperties(RedisProperties.class)
@ConditionalOnClass(name = {
        "org.springframework.data.redis.core.RedisTemplate",
        "io.lettuce.core.ClientOptions"
})
@ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
public class ZeroTrustRedisConfig {

    private final SecurityZeroTrustProperties securityZeroTrustProperties;
    private final RedisProperties redisProperties;

    @Bean
    public ClientResources clientResources() {
        return DefaultClientResources.builder()
                .ioThreadPoolSize(8)  
                .computationThreadPoolSize(8)  
                .commandLatencyRecorder(CommandLatencyRecorder.disabled())
                .build();
    }

    @Bean
    public LettuceClientConfiguration lettuceClientConfiguration(ClientResources clientResources) {
        
        SocketOptions socketOptions = SocketOptions.builder()
                .connectTimeout(Duration.ofMillis(securityZeroTrustProperties.getRedis().getTimeout()))  
                .keepAlive(true)  
                .tcpNoDelay(true)  
                .build();

        ClientOptions clientOptions = ClientOptions.builder()
                .socketOptions(socketOptions)
                .autoReconnect(true)  
                .disconnectedBehavior(ClientOptions.DisconnectedBehavior.REJECT_COMMANDS)  
                .timeoutOptions(TimeoutOptions.enabled(Duration.ofMillis(securityZeroTrustProperties.getRedis().getTimeout())))  
                .build();

        org.apache.commons.pool2.impl.GenericObjectPoolConfig poolConfig = 
                new org.apache.commons.pool2.impl.GenericObjectPoolConfig();
        poolConfig.setMaxTotal(100);  
        poolConfig.setMaxIdle(50);    
        poolConfig.setMinIdle(10);    
        poolConfig.setMaxWaitMillis(securityZeroTrustProperties.getRedis().getTimeout());  
        poolConfig.setTestOnBorrow(false);  
        poolConfig.setTestOnReturn(false);  
        poolConfig.setTestWhileIdle(true);  
        poolConfig.setTimeBetweenEvictionRunsMillis(30000);  

        return LettucePoolingClientConfiguration.builder()
                        .poolConfig(poolConfig)
                        .clientOptions(clientOptions)
                        .clientResources(clientResources)
                        .commandTimeout(Duration.ofMillis(securityZeroTrustProperties.getRedis().getTimeout()))
                        .build();
    }

    @Bean
    public RedisConnectionFactory redisConnectionFactory(LettuceClientConfiguration lettuceClientConfiguration) {
        RedisStandaloneConfiguration redisConfig = new RedisStandaloneConfiguration();
        redisConfig.setHostName(redisProperties.getHost());
        redisConfig.setPort(redisProperties.getPort());
        String redisPassword = redisProperties.getPassword();
        if (redisPassword != null && !redisPassword.isEmpty()) {
            redisConfig.setPassword(redisPassword);
        }
        
        return new LettuceConnectionFactory(redisConfig, lettuceClientConfiguration);
    }

    @Bean(name = "stateMachineRedisTemplate")
    public RedisTemplate<String, Object> stateMachineRedisTemplate(RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(redisConnectionFactory);

        StringRedisSerializer stringSerializer = new StringRedisSerializer();
        template.setKeySerializer(stringSerializer);
        template.setHashKeySerializer(stringSerializer);
        template.setValueSerializer(stringSerializer);
        template.setHashValueSerializer(stringSerializer);
        template.setEnableTransactionSupport(false);

        template.afterPropertiesSet();
        return template;
    }
}