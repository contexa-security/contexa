package io.contexa.contexacore.infra.redis;

import io.contexa.contexacore.soar.notification.SoarApprovalNotifier;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.data.redis.listener.adapter.MessageListenerAdapter;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

/**
 * 통합 Redis 설정 - 간소화 버전
 *
 * 삭제/수정 사항:
 * - @ConditionalOnMissingBean 제거 (불필요)
 * - stateMachinePersistRedisTemplate 삭제 (사용 안함)
 * - 중복된 설정 제거
 */
@Slf4j
@Configuration
@ConditionalOnClass(RedisTemplate.class)
@AutoConfigureAfter(RedisAutoConfiguration.class)
public class UnifiedRedisConfiguration {

    // SOAR 승인 요청 알림 채널 이름
    public static final String SOAR_APPROVAL_CHANNEL = "soar:approval:requests";

    /**
     * 범용 RedisTemplate (JSON 직렬화)
     * - 일반 데이터 저장 (타입 정보 포함)
     */
    @Bean(name = "generalRedisTemplate")
    @Primary
    public RedisTemplate<String, Object> generalRedisTemplate(RedisConnectionFactory connectionFactory) {
        log.info("Creating general purpose RedisTemplate with JSON serialization");

        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        // ObjectMapper 설정 - LocalDateTime 지원 및 다형성 타입 처리
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        objectMapper.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);

        // 다형성 타입 처리를 위한 설정 (BaselineVector 등의 직렬화를 위해)
        objectMapper.activateDefaultTyping(
            BasicPolymorphicTypeValidator.builder()
                .allowIfSubType(Object.class)
                .build(),
            ObjectMapper.DefaultTyping.NON_FINAL
        );

        // 직렬화 설정
        StringRedisSerializer stringSerializer = new StringRedisSerializer();
        GenericJackson2JsonRedisSerializer jsonSerializer = new GenericJackson2JsonRedisSerializer(objectMapper);

        template.setKeySerializer(stringSerializer);
        template.setHashKeySerializer(stringSerializer);
        template.setValueSerializer(jsonSerializer);
        template.setHashValueSerializer(jsonSerializer);
        template.setDefaultSerializer(jsonSerializer);

        // 중요: 트랜잭션 비활성화 (연결 재사용)
        template.setEnableTransactionSupport(false);

        template.afterPropertiesSet();
        return template;
    }

    /**
     * 이벤트 발행 전용 RedisTemplate (타입 정보 없는 JSON 직렬화)
     * - 보안 이벤트 발행
     * - Pub/Sub 메시지
     */
    @Bean(name = "eventRedisTemplate")
    public RedisTemplate<String, Object> eventRedisTemplate(RedisConnectionFactory connectionFactory) {
        log.info("Creating event publishing RedisTemplate without type information");

        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        // ObjectMapper 설정 - 타입 정보 없이
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        objectMapper.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);

        // 타입 정보 포함 안함!

        // 직렬화 설정
        StringRedisSerializer stringSerializer = new StringRedisSerializer();
        GenericJackson2JsonRedisSerializer jsonSerializer = new GenericJackson2JsonRedisSerializer(objectMapper);

        template.setKeySerializer(stringSerializer);
        template.setHashKeySerializer(stringSerializer);
        template.setValueSerializer(jsonSerializer);
        template.setHashValueSerializer(jsonSerializer);
        template.setDefaultSerializer(jsonSerializer);

        // 트랜잭션 비활성화
        template.setEnableTransactionSupport(false);

        template.afterPropertiesSet();
        return template;
    }

    @Bean
    @Primary
    public StringRedisTemplate stringRedisTemplate(RedisConnectionFactory connectionFactory) {
        StringRedisTemplate template = new StringRedisTemplate();
        template.setConnectionFactory(connectionFactory);
        template.setEnableTransactionSupport(false);  // 이거!
        template.afterPropertiesSet();
        return template;
    }

    /**
     * Redis 메시지 리스너 컨테이너
     */
    @Bean
    public RedisMessageListenerContainer redisMessageListenerContainer(
            RedisConnectionFactory connectionFactory,
            SoarApprovalNotifier soarApprovalNotifier // SoarApprovalNotifier 주입
    ) {
        log.info("Creating Redis message listener container");

        RedisMessageListenerContainer container = new RedisMessageListenerContainer();
        container.setConnectionFactory(connectionFactory);

        // SoarApprovalNotifier를 리스너로 등록
        // MessageListenerAdapter를 사용하여 특정 메서드를 호출하도록 설정
        MessageListenerAdapter listenerAdapter = new MessageListenerAdapter(soarApprovalNotifier, "receiveApprovalNotification");
        listenerAdapter.setSerializer(generalRedisTemplate(connectionFactory).getValueSerializer()); // JSON 직렬화 사용

        container.addMessageListener(listenerAdapter, new ChannelTopic(SOAR_APPROVAL_CHANNEL));

        return container;
    }

    /**
     * Trust Score 전용 RedisTemplate (Double 타입)
     * Zero Trust 보안 모델의 신뢰도 점수 저장용
     */
    @Bean(name = "trustScoreRedisTemplate")
    public RedisTemplate<String, Double> trustScoreRedisTemplate(RedisConnectionFactory connectionFactory) {
        log.info("Creating trust score RedisTemplate for Zero Trust security");
        
        RedisTemplate<String, Double> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        
        // 직렬화 설정
        StringRedisSerializer stringSerializer = new StringRedisSerializer();
        
        template.setKeySerializer(stringSerializer);
        template.setHashKeySerializer(stringSerializer);
        template.setValueSerializer(stringSerializer); // Double을 String으로 직렬화
        template.setHashValueSerializer(stringSerializer);
        template.setDefaultSerializer(stringSerializer);
        
        // 트랜잭션 비활성화
        template.setEnableTransactionSupport(false);
        
        template.afterPropertiesSet();
        return template;
    }

    @Bean
    public RedisDistributedLockService redisDistributedLockService(
            @Autowired(required = false) RedisTemplate<String, Object> redisTemplate) {

        if (redisTemplate != null) {
            log.info("Creating RedisDistributedLockService");
            return new RedisDistributedLockService(redisTemplate);
        }
        return null;
    }
}