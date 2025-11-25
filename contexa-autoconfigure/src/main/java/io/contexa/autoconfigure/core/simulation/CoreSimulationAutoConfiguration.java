package io.contexa.autoconfigure.core.simulation;

import io.contexa.autoconfigure.core.infrastructure.CoreInfrastructureAutoConfiguration;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.infra.SimulationDataInitializer;
import io.contexa.contexacore.repository.ApprovalNotificationRepository;
import io.contexa.contexacore.repository.AttackResultRepository;
import io.contexa.contexacore.repository.SecurityActionRepository;
import io.contexa.contexacore.repository.SecurityIncidentRepository;
import io.contexa.contexacore.repository.SoarApprovalRequestRepository;
import io.contexa.contexacore.repository.ThreatIndicatorRepository;
import io.contexa.contexacore.simulation.config.SimulationWebSocketConfig;
import io.contexa.contexacore.simulation.factory.AttackStrategyFactory;
import io.contexa.contexacore.simulation.generator.AttackScenarioGenerator;
import io.contexa.contexacore.simulation.interceptor.SimulationModeInterceptor;
import io.contexa.contexacore.simulation.service.DualModeSimulationService;
import io.contexa.contexacore.simulation.service.SimulationStatisticsService;
import io.contexa.contexacore.simulation.tracker.DataBreachTracker;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.connection.stream.MapRecord;
import org.springframework.data.redis.connection.stream.ObjectRecord;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.stream.StreamMessageListenerContainer;
import org.springframework.data.redis.stream.StreamMessageListenerContainer.StreamMessageListenerContainerOptions;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

import java.time.Duration;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

/**
 * Core Simulation AutoConfiguration
 *
 * Contexa 프레임워크의 Simulation 관련 자동 구성을 제공합니다.
 * @Bean 방식으로 Simulation 서비스들을 명시적으로 등록합니다.
 *
 * 포함된 Configuration:
 * - SimulationWebSocketConfig (Import) - WebSocket 설정
 * - Simulation Infrastructure - 직접 bean 등록 (6개)
 *
 * 포함된 컴포넌트 (9개):
 * Infrastructure (6개):
 * - simulationExecutor - ThreadPoolTaskExecutor
 * - simulationScheduler - ScheduledExecutorService
 * - taskScheduler - TaskScheduler
 * - redisStreamContainer - StreamMessageListenerContainer
 * - simulationMetricsConfig - SimulationMetricsConfig
 * - simulationParameters - SimulationParameters
 *
 * Services (4개):
 * - SimulationStatisticsService - 시뮬레이션 통계 서비스
 * - DualModeSimulationService - 이중 모드 시뮬레이션 서비스
 * - SimulationDataInitializer - 시뮬레이션 데이터 초기화 (조건부)
 * - SimulationModeInterceptor - 시뮬레이션 모드 인터셉터
 *
 * 활성화 조건:
 * contexa:
 *   simulation:
 *     enabled: false  (기본값: 비활성화)
 *
 * @since 0.1.0-ALPHA
 */
@Slf4j
@AutoConfiguration
@AutoConfigureAfter(CoreInfrastructureAutoConfiguration.class)
@ConditionalOnProperty(
    prefix = "contexa.simulation",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
@EnableConfigurationProperties(ContexaProperties.class)
@Import({
    SimulationWebSocketConfig.class
})
public class CoreSimulationAutoConfiguration {

    // Redis Stream 설정
    @Value("${security.pipeline.redis.stream-key:security-events-stream}")
    private String redisStreamKey;

    @Value("${security.pipeline.redis.consumer-group:security-simulation-consumers}")
    private String redisConsumerGroup;

    // 스레드 풀 설정
    @Value("${simulation.executor.core-pool-size:10}")
    private int corePoolSize;

    @Value("${simulation.executor.max-pool-size:50}")
    private int maxPoolSize;

    @Value("${simulation.executor.queue-capacity:100}")
    private int queueCapacity;

    @Value("${simulation.scheduler.pool-size:5}")
    private int schedulerPoolSize;

    public CoreSimulationAutoConfiguration() {
        log.info("=== CoreSimulationAutoConfiguration initialized ===");
    }

    /**
     * 1. SimulationStatisticsService - 시뮬레이션 통계 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public SimulationStatisticsService simulationStatisticsService(
            RedisTemplate<String, Object> redisTemplate,
            StringRedisTemplate stringRedisTemplate) {
        return new SimulationStatisticsService(redisTemplate, stringRedisTemplate);
    }

    /**
     * 2. DualModeSimulationService - 이중 모드 시뮬레이션 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public DualModeSimulationService dualModeSimulationService(
            AttackStrategyFactory strategyFactory,
            AttackScenarioGenerator scenarioGenerator,
            AttackResultRepository attackResultRepository,
            DataBreachTracker dataBreachTracker) {
        return new DualModeSimulationService(
            strategyFactory, scenarioGenerator, attackResultRepository, dataBreachTracker
        );
    }

    /**
     * 3. SimulationDataInitializer - 시뮬레이션 데이터 초기화 (조건부)
     */
    @Bean
    @ConditionalOnProperty(prefix = "contexa.simulation.data", name = "enabled", havingValue = "true")
    @ConditionalOnMissingBean
    public SimulationDataInitializer simulationDataInitializer(
            SecurityIncidentRepository securityIncidentRepository,
            ThreatIndicatorRepository threatIndicatorRepository,
            SecurityActionRepository securityActionRepository,
            SoarApprovalRequestRepository soarApprovalRequestRepository,
            ApprovalNotificationRepository approvalNotificationRepository,
            @Autowired(required = false) KafkaTemplate<String, Object> kafkaTemplate) {
        return new SimulationDataInitializer(
            securityIncidentRepository, threatIndicatorRepository, securityActionRepository,
            soarApprovalRequestRepository, approvalNotificationRepository, kafkaTemplate
        );
    }

    /**
     * 4. SimulationModeInterceptor - 시뮬레이션 모드 인터셉터
     */
    @Bean
    @ConditionalOnMissingBean
    public SimulationModeInterceptor simulationModeInterceptor() {
        return new SimulationModeInterceptor();
    }

    // ===== Infrastructure Beans (6개) =====

    /**
     * Infrastructure 1: simulationExecutor - 시뮬레이션 실행용 ThreadPoolTaskExecutor
     * 비동기 작업 처리를 위한 스레드 풀
     */
    @Bean(name = "simulationExecutor")
    @ConditionalOnMissingBean(name = "simulationExecutor")
    public Executor simulationExecutor() {
        log.info("시뮬레이션 Executor 생성: core={}, max={}, queue={}",
            corePoolSize, maxPoolSize, queueCapacity);

        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(corePoolSize);
        executor.setMaxPoolSize(maxPoolSize);
        executor.setQueueCapacity(queueCapacity);
        executor.setThreadNamePrefix("sim-exec-");
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(30);
        executor.initialize();

        return executor;
    }

    /**
     * Infrastructure 2: simulationScheduler - 스케줄링용 ScheduledExecutorService
     * 주기적인 작업 실행
     */
    @Bean(name = "simulationScheduler", destroyMethod = "shutdown")
    @ConditionalOnMissingBean(name = "simulationScheduler")
    public ScheduledExecutorService simulationScheduler() {
        log.info("시뮬레이션 Scheduler 생성: poolSize={}", schedulerPoolSize);
        return Executors.newScheduledThreadPool(schedulerPoolSize, r -> {
            Thread thread = new Thread(r);
            thread.setName("sim-sched-" + thread.getId());
            thread.setDaemon(true);
            return thread;
        });
    }

    /**
     * Infrastructure 3: taskScheduler - Spring TaskScheduler
     * @Scheduled 어노테이션 지원
     */
    @Bean
    @ConditionalOnMissingBean(TaskScheduler.class)
    public TaskScheduler taskScheduler() {
        ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();
        scheduler.setPoolSize(3);
        scheduler.setThreadNamePrefix("task-sched-");
        scheduler.setWaitForTasksToCompleteOnShutdown(true);
        scheduler.setAwaitTerminationSeconds(20);
        scheduler.initialize();
        return scheduler;
    }

    /**
     * Infrastructure 4: redisStreamContainer - Redis Stream 리스너 컨테이너
     * 실시간 이벤트 스트리밍 처리
     */
    @Bean
    @ConditionalOnMissingBean
    public StreamMessageListenerContainer<String, ObjectRecord<String, MapRecord>> redisStreamContainer(
            RedisTemplate<String, Object> redisTemplate) {

        log.info("Redis Stream 리스너 컨테이너 생성: stream={}, group={}",
            redisStreamKey, redisConsumerGroup);

        StreamMessageListenerContainerOptions<String, ObjectRecord<String, MapRecord>> options =
            StreamMessageListenerContainerOptions
                .builder()
                .pollTimeout(Duration.ofSeconds(1))
                .targetType(MapRecord.class)
                .build();

        StreamMessageListenerContainer<String, ObjectRecord<String, MapRecord>> container =
            StreamMessageListenerContainer.create(
                redisTemplate.getConnectionFactory(),
                options
            );

        return container;
    }

    /**
     * Infrastructure 5: simulationMetricsConfig - 시뮬레이션 메트릭 설정
     */
    @Bean
    @ConditionalOnMissingBean
    public SimulationMetricsConfig simulationMetricsConfig() {
        return SimulationMetricsConfig.builder()
            .enableMetrics(true)
            .metricsInterval(5000)
            .enablePrometheus(isPrometheusEnabled())
            .enableGrafana(isGrafanaEnabled())
            .build();
    }

    /**
     * Infrastructure 6: simulationParameters - 시뮬레이션 파라미터 설정
     */
    @Bean
    @ConditionalOnMissingBean
    public SimulationParameters simulationParameters() {
        return SimulationParameters.builder()
            .defaultAttackRate(10)
            .maxConcurrentAttacks(100)
            .attackDiversity(0.8)
            .layer1Threshold(4.0)
            .layer2Threshold(7.0)
            .escalationDelay(2000)
            .soarApprovalTimeout(60000)
            .asyncExecutionEnabled(true)
            .maxPendingApprovals(20)
            .monitoringInterval(5000)
            .anomalyDetectionEnabled(true)
            .alertingEnabled(isAlertingEnabled())
            .build();
    }

    // ===== Helper Methods =====

    private boolean isPrometheusEnabled() {
        String enabled = System.getenv("PROMETHEUS_ENABLED");
        return "true".equalsIgnoreCase(enabled) || "1".equals(enabled);
    }

    private boolean isGrafanaEnabled() {
        String enabled = System.getenv("GRAFANA_ENABLED");
        return "true".equalsIgnoreCase(enabled) || "1".equals(enabled);
    }

    private boolean isAlertingEnabled() {
        String enabled = System.getenv("ALERTING_ENABLED");
        return "true".equalsIgnoreCase(enabled) || "1".equals(enabled);
    }

    // ===== Inner Classes =====

    /**
     * 시뮬레이션 메트릭 설정 클래스
     */
    @lombok.Data
    @lombok.Builder
    public static class SimulationMetricsConfig {
        private boolean enableMetrics;
        private int metricsInterval;
        private boolean enablePrometheus;
        private boolean enableGrafana;
    }

    /**
     * 시뮬레이션 파라미터 클래스
     */
    @lombok.Data
    @lombok.Builder
    public static class SimulationParameters {
        private int defaultAttackRate;
        private int maxConcurrentAttacks;
        private double attackDiversity;
        private double layer1Threshold;
        private double layer2Threshold;
        private int escalationDelay;
        private int soarApprovalTimeout;
        private boolean asyncExecutionEnabled;
        private int maxPendingApprovals;
        private int monitoringInterval;
        private boolean anomalyDetectionEnabled;
        private boolean alertingEnabled;
    }
}
