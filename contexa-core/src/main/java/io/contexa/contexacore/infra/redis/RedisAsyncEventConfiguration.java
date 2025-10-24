package io.contexa.contexacore.infra.redis;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * Redis 및 비동기 이벤트 처리 설정 클래스
 * 
 * Redis를 통한 이벤트 발행과 비동기 처리를 위한 ThreadPool 설정을 관리합니다.
 * Zero Trust 보안 모델을 위한 실시간 이벤트 분석을 지원합니다.
 */
@Slf4j
@Configuration
public class RedisAsyncEventConfiguration {
    
    /**
     * Redis Template 설정
     * 
     * JSON 직렬화를 사용하여 객체를 저장하고 조회합니다.
     */
    @Bean
    public RedisTemplate<String, Object> redisEventTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        
        // Jackson2JsonRedisSerializer 설정
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        
        Jackson2JsonRedisSerializer<Object> jackson2JsonRedisSerializer = 
            new Jackson2JsonRedisSerializer<>(objectMapper, Object.class);
        
        // Key는 String, Value는 JSON으로 직렬화
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(jackson2JsonRedisSerializer);
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setHashValueSerializer(jackson2JsonRedisSerializer);
        
        template.afterPropertiesSet();
        
        log.info("Redis Template configured for event publishing");
        
        return template;
    }
    

    
    /**
     * ObjectMapper 빈 (이미 존재하지 않는 경우)
     */
    @Bean
    public ObjectMapper eventObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        return mapper;
    }
    
    /**
     * Critical 이벤트 처리를 위한 우선순위 Executor
     * 
     * 즉시 처리가 필요한 고위험 이벤트를 위한 전용 스레드 풀
     */
    @Bean(name = "criticalEventExecutor")
    public Executor criticalEventExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        
        // Critical 이벤트는 항상 즉시 처리
        executor.setCorePoolSize(Runtime.getRuntime().availableProcessors());
        executor.setMaxPoolSize(Runtime.getRuntime().availableProcessors() * 2);
        executor.setQueueCapacity(1000); // 작은 큐로 빠른 처리 보장
        
        executor.setThreadNamePrefix("CriticalEvent-");
        
        // 큐가 가득 찼을 때: 새 스레드 생성 또는 호출자 실행
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        
        executor.setKeepAliveSeconds(30);
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(10);
        
        executor.initialize();
        return executor;
    }
}