package io.contexa.contexaidentity.config;

import io.lettuce.core.ClientOptions;
import io.lettuce.core.SocketOptions;
import io.lettuce.core.TimeoutOptions;
import io.lettuce.core.resource.ClientResources;
import io.lettuce.core.resource.DefaultClientResources;
import org.springframework.beans.factory.annotation.Value;
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
public class ZeroTrustRedisConfig {
    
    @Value("${spring.data.redis.host:localhost}")
    private String redisHost;
    
    @Value("${spring.data.redis.port:6379}")
    private int redisPort;
    
    @Value("${spring.data.redis.password:}")
    private String redisPassword;
    
    @Value("${security.zerotrust.redis.timeout:5}")
    private long redisTimeoutMs;
    
    
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
                .connectTimeout(Duration.ofMillis(redisTimeoutMs))  
                .keepAlive(true)  
                .tcpNoDelay(true)  
                .build();
        
        
        ClientOptions clientOptions = ClientOptions.builder()
                .socketOptions(socketOptions)
                .autoReconnect(true)  
                .disconnectedBehavior(ClientOptions.DisconnectedBehavior.REJECT_COMMANDS)  
                .timeoutOptions(TimeoutOptions.enabled(Duration.ofMillis(redisTimeoutMs)))  
                .build();
        
        
        org.apache.commons.pool2.impl.GenericObjectPoolConfig poolConfig = 
                new org.apache.commons.pool2.impl.GenericObjectPoolConfig();
        poolConfig.setMaxTotal(100);  
        poolConfig.setMaxIdle(50);    
        poolConfig.setMinIdle(10);    
        poolConfig.setMaxWaitMillis(redisTimeoutMs);  
        poolConfig.setTestOnBorrow(false);  
        poolConfig.setTestOnReturn(false);  
        poolConfig.setTestWhileIdle(true);  
        poolConfig.setTimeBetweenEvictionRunsMillis(30000);  
        
        
        return LettucePoolingClientConfiguration.builder()
                        .poolConfig(poolConfig)
                        .clientOptions(clientOptions)
                        .clientResources(clientResources)
                        .commandTimeout(Duration.ofMillis(redisTimeoutMs))
                        .build();
    }
    
    
    @Bean
    public RedisConnectionFactory redisConnectionFactory(LettuceClientConfiguration lettuceClientConfiguration) {
        RedisStandaloneConfiguration redisConfig = new RedisStandaloneConfiguration();
        redisConfig.setHostName(redisHost);
        redisConfig.setPort(redisPort);
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