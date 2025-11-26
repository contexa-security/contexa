package io.contexa.contexacommon.config.redis;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

/**
 * 공통 Redis 자동 설정 (Common Redis Auto Configuration)
 *
 * 모든 contexa 모듈에서 공통으로 사용하는 Redis 빈 정의
 *
 * 제공 빈:
 * - generalRedisTemplate: 범용 JSON 직렬화 (타입 정보 포함)
 * - eventRedisTemplate: 이벤트 발행용 (타입 정보 제외)
 * - stringRedisTemplate: 문자열 전용
 * - trustScoreRedisTemplate: Zero Trust 신뢰도 점수 전용
 *
 * @since 0.1.0-ALPHA
 */
@Slf4j
@AutoConfiguration
@ConditionalOnClass(RedisTemplate.class)
@AutoConfigureAfter(RedisAutoConfiguration.class)
public class CommonRedisAutoConfiguration {

    /**
     * 범용 RedisTemplate (JSON 직렬화, 타입 정보 포함)
     *
     * 용도:
     * - 일반 데이터 저장 (BaselineVector, HCADContext 등)
     * - 복잡한 객체 직렬화
     * - 세션 데이터 저장
     *
     * 특징:
     * - LocalDateTime 지원 (JavaTimeModule)
     * - 다형성 타입 처리 (activateDefaultTyping)
     * - 트랜잭션 비활성화 (성능 최적화)
     */
    @Bean(name = "generalRedisTemplate")
    @Primary
    @ConditionalOnMissingBean(name = "generalRedisTemplate")
    public RedisTemplate<String, Object> generalRedisTemplate(RedisConnectionFactory connectionFactory) {
        log.info("Creating common generalRedisTemplate with JSON serialization");

        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        ObjectMapper objectMapper = createBaseObjectMapper();
        objectMapper.activateDefaultTyping(
            BasicPolymorphicTypeValidator.builder()
                .allowIfSubType(Object.class)
                .build(),
            ObjectMapper.DefaultTyping.NON_FINAL
        );

        StringRedisSerializer stringSerializer = new StringRedisSerializer();
        GenericJackson2JsonRedisSerializer jsonSerializer =
            new GenericJackson2JsonRedisSerializer(objectMapper);

        template.setKeySerializer(stringSerializer);
        template.setHashKeySerializer(stringSerializer);
        template.setValueSerializer(jsonSerializer);
        template.setHashValueSerializer(jsonSerializer);
        template.setDefaultSerializer(jsonSerializer);
        template.setEnableTransactionSupport(false);

        template.afterPropertiesSet();
        return template;
    }

    /**
     * 이벤트 발행 전용 RedisTemplate (JSON 직렬화, 타입 정보 제외)
     *
     * 용도:
     * - 보안 이벤트 발행
     * - Pub/Sub 메시지
     * - 이벤트 스트림
     *
     * 특징:
     * - 타입 정보 포함하지 않음 (경량화)
     * - 이벤트 소비자 호환성 향상
     */
    @Bean(name = "eventRedisTemplate")
    @ConditionalOnMissingBean(name = "eventRedisTemplate")
    public RedisTemplate<String, Object> eventRedisTemplate(RedisConnectionFactory connectionFactory) {
        log.info("Creating common eventRedisTemplate without type information");

        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        ObjectMapper objectMapper = createBaseObjectMapper();

        StringRedisSerializer stringSerializer = new StringRedisSerializer();
        GenericJackson2JsonRedisSerializer jsonSerializer =
            new GenericJackson2JsonRedisSerializer(objectMapper);

        template.setKeySerializer(stringSerializer);
        template.setHashKeySerializer(stringSerializer);
        template.setValueSerializer(jsonSerializer);
        template.setHashValueSerializer(jsonSerializer);
        template.setDefaultSerializer(jsonSerializer);
        template.setEnableTransactionSupport(false);

        template.afterPropertiesSet();
        return template;
    }

    /**
     * 문자열 전용 RedisTemplate
     *
     * 용도:
     * - 단순 문자열 키-값 저장
     * - 카운터
     * - 플래그
     */
    @Bean
    @ConditionalOnMissingBean(StringRedisTemplate.class)
    public StringRedisTemplate stringRedisTemplate(RedisConnectionFactory connectionFactory) {
        log.info("Creating common stringRedisTemplate");

        StringRedisTemplate template = new StringRedisTemplate();
        template.setConnectionFactory(connectionFactory);
        template.setEnableTransactionSupport(false);
        template.afterPropertiesSet();
        return template;
    }

    /**
     * Trust Score 전용 RedisTemplate (Double 타입)
     *
     * 용도:
     * - Zero Trust 보안 모델의 신뢰도 점수 저장
     * - 실시간 위협 점수 계산
     *
     * 특징:
     * - Double을 String으로 직렬화 (최소 오버헤드)
     * - 성능 최적화
     */
    @Bean(name = "trustScoreRedisTemplate")
    @ConditionalOnMissingBean(name = "trustScoreRedisTemplate")
    public RedisTemplate<String, Double> trustScoreRedisTemplate(RedisConnectionFactory connectionFactory) {
        log.info("Creating common trustScoreRedisTemplate for Zero Trust security");

        RedisTemplate<String, Double> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        StringRedisSerializer stringSerializer = new StringRedisSerializer();

        template.setKeySerializer(stringSerializer);
        template.setHashKeySerializer(stringSerializer);
        template.setValueSerializer(stringSerializer);
        template.setHashValueSerializer(stringSerializer);
        template.setDefaultSerializer(stringSerializer);
        template.setEnableTransactionSupport(false);

        template.afterPropertiesSet();
        return template;
    }

    /**
     * 공통 ObjectMapper 생성
     *
     * 설정:
     * - JavaTimeModule 등록 (LocalDateTime 지원)
     * - 날짜를 타임스탬프가 아닌 문자열로 직렬화
     * - 모든 필드 접근 가능 (private 포함)
     */
    private ObjectMapper createBaseObjectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        objectMapper.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
        return objectMapper;
    }
}
