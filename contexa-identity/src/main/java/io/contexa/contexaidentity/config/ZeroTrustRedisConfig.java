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

/**
 * Zero Trust Redis 성능 최적화 설정
 * 
 * 목표: 5ms 이내 응답 시간 달성
 * 
 * 최적화 전략:
 * 1. Connection Pooling - 연결 재사용으로 지연 감소
 * 2. Pipeline Operations - 배치 처리로 RTT 감소
 * 3. Command Timeout - 빠른 실패로 응답성 향상
 * 4. TCP NoDelay - Nagle 알고리즘 비활성화로 지연 감소
 * 5. Keep-Alive - 연결 유지로 재연결 오버헤드 감소
 * 
 * @author contexa
 * @since 2.0
 */
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
    
    /**
     * 최적화된 Redis 클라이언트 리소스 설정
     */
    @Bean
    public ClientResources clientResources() {
        return DefaultClientResources.builder()
                .ioThreadPoolSize(8)  // I/O 스레드 풀 크기
                .computationThreadPoolSize(8)  // 계산 스레드 풀 크기
                .build();
    }
    
    /**
     * 최적화된 Lettuce 클라이언트 설정
     */
    @Bean
    public LettuceClientConfiguration lettuceClientConfiguration(ClientResources clientResources) {
        // 소켓 옵션 설정 - TCP 레벨 최적화
        SocketOptions socketOptions = SocketOptions.builder()
                .connectTimeout(Duration.ofMillis(redisTimeoutMs))  // 연결 타임아웃
                .keepAlive(true)  // TCP Keep-Alive 활성화
                .tcpNoDelay(true)  // Nagle 알고리즘 비활성화 (지연 감소)
                .build();
        
        // 클라이언트 옵션 설정
        ClientOptions clientOptions = ClientOptions.builder()
                .socketOptions(socketOptions)
                .autoReconnect(true)  // 자동 재연결
                .disconnectedBehavior(ClientOptions.DisconnectedBehavior.REJECT_COMMANDS)  // 연결 끊김시 명령 거부
                .timeoutOptions(TimeoutOptions.enabled(Duration.ofMillis(redisTimeoutMs)))  // 명령 타임아웃
                .build();
        
        // Pool 설정 최적화
        org.apache.commons.pool2.impl.GenericObjectPoolConfig poolConfig = 
                new org.apache.commons.pool2.impl.GenericObjectPoolConfig();
        poolConfig.setMaxTotal(100);  // 최대 연결 수
        poolConfig.setMaxIdle(50);    // 최대 유휴 연결 수
        poolConfig.setMinIdle(10);    // 최소 유휴 연결 수
        poolConfig.setMaxWaitMillis(redisTimeoutMs);  // 연결 대기 시간
        poolConfig.setTestOnBorrow(false);  // 대여시 테스트 비활성화 (성능 향상)
        poolConfig.setTestOnReturn(false);  // 반환시 테스트 비활성화 (성능 향상)
        poolConfig.setTestWhileIdle(true);  // 유휴 연결 테스트 활성화
        poolConfig.setTimeBetweenEvictionRunsMillis(30000);  // 유휴 연결 제거 주기 (30초)
        
        // Connection Pooling 설정 - 연결 재사용으로 성능 향상
        return LettucePoolingClientConfiguration.builder()
                        .poolConfig(poolConfig)
                        .clientOptions(clientOptions)
                        .clientResources(clientResources)
                        .commandTimeout(Duration.ofMillis(redisTimeoutMs))
                        .build();
    }
    
    /**
     * 최적화된 Redis Connection Factory
     */
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
    
    /**
     * StateMachine 전용 RedisTemplate
     *
     * 용도:
     * - MFA StateMachine 이벤트 발행
     * - StateMachine 상태 변경 알림
     *
     * 특징:
     * - 이벤트 발행 전용 (타입 정보 제외)
     * - MfaAsyncEventListener에서 사용
     */
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