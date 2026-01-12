package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * Security Plane Agent 설정
 */
@Data
@ConfigurationProperties(prefix = "security.plane")
public class SecurityPlaneProperties {

    /**
     * 에이전트 설정
     */
    @NestedConfigurationProperty
    private AgentSettings agent = new AgentSettings();

    /**
     * Kafka 설정
     */
    @NestedConfigurationProperty
    private KafkaSettings kafka = new KafkaSettings();

    /**
     * 모니터 설정
     */
    @NestedConfigurationProperty
    private MonitorSettings monitor = new MonitorSettings();

    /**
     * 알림 설정
     */
    @NestedConfigurationProperty
    private NotifierSettings notifier = new NotifierSettings();

    /**
     * Redis 설정
     */
    @NestedConfigurationProperty
    private RedisSettings redis = new RedisSettings();

    /**
     * LLM 분석 Executor 설정
     *
     * AI Native v5.0.0: B2B Login Storm 대응
     * 동시 접속이 수천 명이어도 설정된 스레드 수만큼만 LLM API 호출하여 시스템 안정성 보장
     */
    @NestedConfigurationProperty
    private LlmExecutorSettings llmExecutor = new LlmExecutorSettings();

    /**
     * 이벤트 중복 제거 설정
     *
     * AI Native v5.1.0: 라이브러리 형태 지원
     * - @Value 대신 Properties 클래스로 설정
     * - EventDeduplicator에서 사용
     */
    @NestedConfigurationProperty
    private DeduplicationSettings deduplication = new DeduplicationSettings();

    /**
     * 에이전트 설정
     *
     * AI Native v3.3.0: 점수 기반 임계값 제거
     * LLM이 Action (ALLOW/BLOCK/CHALLENGE/ESCALATE)을 직접 결정
     */
    @Data
    public static class AgentSettings {
        private String name = "SecurityPlaneAgent-1";
        private boolean autoStart = true;
        private int maxConcurrentIncidents = 10;
        // AI Native v3.3.0: threatThreshold, similarityThreshold, layer1Threshold, layer2Threshold, autoApproveLowRisk 제거
        private String organizationId = "default-org";
        private String executionMode = "ASYNC";
    }

    /**
     * Kafka 설정
     */
    @Data
    public static class KafkaSettings {
        private String bootstrapServers = "localhost:9092";
        private String groupId = "security-plane-consumer";

        @NestedConfigurationProperty
        private TopicsSettings topics = new TopicsSettings();

        @Data
        public static class TopicsSettings {
            private String securityEvents = "security-events";
            private String threatIndicators = "threat-indicators";
            private String networkEvents = "network-events";
            private String authEvents = "auth-events";
        }
    }

    /**
     * 모니터 설정
     *
     * AI Native v3.3.0: 점수 기반 임계값 제거
     */
    @Data
    public static class MonitorSettings {
        private int queueSize = 10000;
        private int workerThreads = 5;
        private int correlationWindowMinutes = 10;
        // AI Native v3.3.0: threatThreshold 제거
        private boolean autoIncidentCreation = true;
        private int dedupWindowMinutes = 5;
    }

    /**
     * 알림 설정
     *
     * AI Native v3.3.0: 점수 기반 임계값 제거
     */
    @Data
    public static class NotifierSettings {
        private int batchSize = 10;
        private boolean asyncEnabled = true;
        // AI Native v3.3.0: criticalThreshold 제거
    }

    /**
     * Redis 설정
     */
    @Data
    public static class RedisSettings {
        private int batchSize = 50;

        @NestedConfigurationProperty
        private CacheSettings cache = new CacheSettings();

        @NestedConfigurationProperty
        private ChannelSettings channel = new ChannelSettings();

        @Data
        public static class CacheSettings {
            private int ttlMinutes = 60;
        }

        @Data
        public static class ChannelSettings {
            private String securityEvents = "security:events";
            private String threatAlerts = "security:threats";
            private String incidents = "security:incidents";
        }
    }

    /**
     * LLM 분석 Executor 설정
     *
     * AI Native v5.0.0: LLM 분석 Throttling
     * - 동시 접속이 수천 명이어도 설정된 스레드 수만큼만 순차 처리
     * - CallerRunsPolicy: 큐 초과 시 호출 스레드에서 직접 실행 (백프레셔)
     *
     * 확장 가이드: 인스턴스 수 * corePoolSize = 전체 LLM 처리량
     * 예: 3개 인스턴스 * 10 스레드 = 동시 30개 LLM 분석
     */
    @Data
    public static class LlmExecutorSettings {
        /**
         * LLM 분석 동시 처리 스레드 수
         * 기본값: 10 (고정 풀 권장)
         */
        private int corePoolSize = 10;

        /**
         * 최대 스레드 수
         * 기본값: 10 (고정 풀 권장, corePoolSize와 동일하게 설정)
         */
        private int maxPoolSize = 10;

        /**
         * 대기 큐 크기
         * 기본값: 1000 (Consumer Lag 대응)
         * 큐 초과 시 CallerRunsPolicy 적용
         */
        private int queueCapacity = 1000;
    }

    /**
     * 이벤트 중복 제거 설정
     *
     * AI Native v5.1.0: 라이브러리 형태 지원
     * - Caffeine 캐시 기반 고성능 중복 검사
     * - 이벤트 ID + 내용 해시 기반 2단계 중복 제거
     *
     * 설정 경로: security.plane.deduplication.*
     */
    @Data
    public static class DeduplicationSettings {
        /**
         * 중복 제거 활성화 여부
         * 기본값: true
         */
        private boolean enabled = true;

        /**
         * 중복 검사 시간 윈도우 (분)
         * 이 시간 내에 동일한 이벤트는 중복으로 처리
         * 기본값: 5분
         */
        private int windowMinutes = 5;

        /**
         * 중복 제거 캐시 크기
         * Caffeine 캐시 최대 항목 수
         * 기본값: 10000
         */
        private int cacheSize = 10000;
    }
}
