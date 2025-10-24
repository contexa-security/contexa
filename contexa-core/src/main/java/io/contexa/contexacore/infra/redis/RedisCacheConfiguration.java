package io.contexa.contexacore.infra.redis;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.routing.AttackPattern;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

/**
 * Redis 캐시 설정
 * 
 * 임시 메모리 캐시를 대체하는 Redis 분산 캐시 설정입니다.
 * JSON 직렬화를 사용하여 복잡한 객체도 저장 가능합니다.
 */
@Configuration
public class RedisCacheConfiguration {
    
    /**
     * AttackPattern Redis Template 설정
     */
    @Bean
    public RedisTemplate<String, AttackPattern> attackPatternRedisTemplate(
            RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, AttackPattern> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        
        // JSON 직렬화 설정
        ObjectMapper objectMapper = createObjectMapper();
        GenericJackson2JsonRedisSerializer serializer = 
            new GenericJackson2JsonRedisSerializer(objectMapper);
        
        // 키는 String, 값은 JSON으로 직렬화
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(serializer);
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setHashValueSerializer(serializer);
        
        template.afterPropertiesSet();
        return template;
    }
    
    /**
     * PolicyEvolutionProposal Redis Template 설정
     */
    @Bean
    public RedisTemplate<String, PolicyEvolutionProposal> policyProposalRedisTemplate(
            RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, PolicyEvolutionProposal> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        
        // JSON 직렬화 설정
        ObjectMapper objectMapper = createObjectMapper();
        GenericJackson2JsonRedisSerializer serializer = 
            new GenericJackson2JsonRedisSerializer(objectMapper);
        
        // 키는 String, 값은 JSON으로 직렬화
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(serializer);
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setHashValueSerializer(serializer);
        
        template.afterPropertiesSet();
        return template;
    }
    
    /**
     * SecurityEvent Redis Template 설정
     */
    @Bean
    public RedisTemplate<String, SecurityEvent> securityEventRedisTemplate(
            RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, SecurityEvent> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        
        // JSON 직렬화 설정
        ObjectMapper objectMapper = createObjectMapper();
        GenericJackson2JsonRedisSerializer serializer = 
            new GenericJackson2JsonRedisSerializer(objectMapper);
        
        // 키는 String, 값은 JSON으로 직렬화
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(serializer);
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setHashValueSerializer(serializer);
        
        template.afterPropertiesSet();
        return template;
    }
    
    /**
     * ObjectMapper 생성 - JSON 직렬화를 위한 설정
     */
    private ObjectMapper createObjectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        
        // Java 8 Time 모듈 등록 (LocalDateTime 등 지원)
        objectMapper.registerModule(new JavaTimeModule());
        
        // 타입 정보 포함 설정 (역직렬화 시 클래스 타입 보존)
        objectMapper.activateDefaultTyping(
            BasicPolymorphicTypeValidator.builder()
                .allowIfSubType(Object.class)
                .build(),
            ObjectMapper.DefaultTyping.NON_FINAL,
            JsonTypeInfo.As.PROPERTY
        );
        
        return objectMapper;
    }
}