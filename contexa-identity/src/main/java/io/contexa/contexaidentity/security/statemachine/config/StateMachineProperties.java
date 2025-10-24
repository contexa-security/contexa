package io.contexa.contexaidentity.security.statemachine.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * State Machine 설정 프로퍼티
 * - 모든 설정을 한 곳에서 관리
 * - 타입 안전성 보장
 */
@Data
@ConfigurationProperties(prefix = "security.statemachine")
public class StateMachineProperties {

    /**
     * State Machine 활성화 여부
     */
    private boolean enabled = true;

    /**
     * 동작 타임아웃 (초)
     */
    private int operationTimeoutSeconds = 10;

    /**
     * Circuit Breaker 설정
     */
    @NestedConfigurationProperty
    private CircuitBreakerProperties circuitBreaker = new CircuitBreakerProperties();

    /**
     * Pool 설정
     */
    @NestedConfigurationProperty
    private PoolProperties pool = new PoolProperties();

    /**
     * 영속화 설정
     */
    @NestedConfigurationProperty
    private PersistenceProperties persistence = new PersistenceProperties();

    /**
     * 캐시 설정
     */
    @NestedConfigurationProperty
    private CacheProperties cache = new CacheProperties();

    /**
     * 이벤트 설정
     */
    @NestedConfigurationProperty
    private EventsProperties events = new EventsProperties();

    /**
     * MFA 관련 설정
     */
    @NestedConfigurationProperty
    private MfaProperties mfa = new MfaProperties();

    /**
     * Redis 설정
     */
    @NestedConfigurationProperty
    private RedisProperties redis = new RedisProperties();

    /**
     * 분산 락 설정
     */
    @NestedConfigurationProperty
    private DistributedLockProperties distributedLock = new DistributedLockProperties();

    /**
     * Circuit Breaker 설정
     */
    @Data
    public static class CircuitBreakerProperties {
        /**
         * 실패 임계값
         */
        private int failureThreshold = 5;

        /**
         * 타임아웃 (초)
         */
        private int timeoutSeconds = 30;

        /**
         * Half-Open 상태에서 테스트 요청 수
         */
        private int halfOpenRequests = 3;
    }

    /**
     * Pool 설정
     */
    @Data
    public static class PoolProperties {
        /**
         * 코어 풀 크기
         */
        private int coreSize = 10;

        /**
         * 최대 풀 크기
         */
        private int maxSize = 50;

        /**
         * 유휴 시간 (분)
         */
        private long keepAliveTime = 10;

        /**
         * 풀 확장 임계값 (사용률)
         */
        private double expansionThreshold = 0.8;

        /**
         * 풀 축소 임계값 (사용률)
         */
        private double shrinkThreshold = 0.2;
    }

    /**
     * 영속화 설정
     */
    @Data
    public static class PersistenceProperties {
        /**
         * 영속화 타입 (memory, redis, hybrid)
         */
        private String type = "memory";

        /**
         * Fallback 활성화
         */
        private boolean enableFallback = true;

        /**
         * TTL (분)
         */
        private Integer ttlMinutes = 30;

        /**
         * 압축 활성화
         */
        private boolean enableCompression = true;

        /**
         * 압축 임계값 (bytes)
         */
        private int compressionThreshold = 1024;
    }

    /**
     * 캐시 설정
     */
    @Data
    public static class CacheProperties {
        /**
         * 최대 캐시 크기
         */
        private int maxSize = 1000;

        /**
         * 캐시 TTL (분)
         */
        private int ttlMinutes = 5;

        /**
         * 캐시 워밍업 활성화
         */
        private boolean enableWarmup = false;
    }

    /**
     * 이벤트 설정
     */
    @Data
    public static class EventsProperties {
        /**
         * 이벤트 발행 활성화
         */
        private boolean enabled = true;

        /**
         * 이벤트 타입 (local, redis, kafka)
         */
        private String type = "local";

        /**
         * 배치 크기
         */
        private int batchSize = 100;

        /**
         * 배치 인터벌 (밀리초)
         */
        private int batchIntervalMs = 100;

        /**
         * 백프레셔 임계값
         */
        private int backpressureThreshold = 1000;
    }

    /**
     * MFA 설정
     */
    @Data
    public static class MfaProperties {
        /**
         * 메트릭 수집 활성화
         */
        private boolean enableMetrics = true;

        /**
         * 최대 재시도 횟수
         */
        private Integer maxRetries = 3;

        /**
         * 세션 타임아웃 (분)
         */
        private Integer sessionTimeoutMinutes = 30;

        /**
         * 동시 세션 제한
         */
        private Integer maxConcurrentSessions = 1000;

        /**
         * 상태 전이 타임아웃 (초)
         */
        private Integer transitionTimeoutSeconds = 5;
    }

    /**
     * Redis 설정
     */
    @Data
    public static class RedisProperties {
        /**
         * Redis 사용 여부
         */
        private boolean enabled = false;

        /**
         * TTL (분)
         */
        private Integer ttlMinutes = 30;

        /**
         * 키 프리픽스
         */
        private String keyPrefix = "mfa:statemachine:";

        /**
         * 연결 타임아웃 (밀리초)
         */
        private int connectionTimeoutMs = 2000;

        /**
         * 명령 타임아웃 (밀리초)
         */
        private int commandTimeoutMs = 1000;
    }

    /**
     * 분산 락 설정
     */
    @Data
    public static class DistributedLockProperties {
        /**
         * 분산 락 활성화
         */
        private boolean enabled = true;

        /**
         * 락 타임아웃 (초)
         */
        private int timeoutSeconds = 10;

        /**
         * 최대 재시도 횟수
         */
        private int maxRetryAttempts = 3;

        /**
         * 재시도 간격 (밀리초)
         */
        private int retryIntervalMs = 100;

        /**
         * 데드락 감지 활성화
         */
        private boolean enableDeadlockDetection = true;
    }
}