package io.contexa.contexaidentity.config;

import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.lettuce.core.ClientOptions;
import io.lettuce.core.SocketOptions;
import io.lettuce.core.TimeoutOptions;
import io.lettuce.core.resource.ClientResources;
import io.lettuce.core.resource.DefaultClientResources;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettucePoolingClientConfiguration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.time.Duration;

@Configuration
@RequiredArgsConstructor
@ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
public class ZeroTrustRedisConfig {

    private final SecurityZeroTrustProperties securityZeroTrustProperties;
    private final RedisProperties redisProperties;

    @Bean
    public ClientResources clientResources() {
        return DefaultClientResources.builder()
                .ioThreadPoolSize(8)  
                .computationThreadPoolSize(8)  
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