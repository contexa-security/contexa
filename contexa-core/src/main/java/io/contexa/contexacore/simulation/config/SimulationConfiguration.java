package io.contexa.contexacore.simulation.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.stream.Consumer;
import org.springframework.data.redis.connection.stream.MapRecord;
import org.springframework.data.redis.connection.stream.ObjectRecord;
import org.springframework.data.redis.connection.stream.ReadOffset;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.stream.StreamMessageListenerContainer;
import org.springframework.data.redis.stream.StreamMessageListenerContainer.StreamMessageListenerContainerOptions;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;

/**
 * 시뮬레이션 설정 클래스
 * 
 * 자율보안지능 시뮬레이션 시스템의 모든 설정을 관리합니다.
 * ExecutorService, Scheduler, Redis Stream, Kafka 등의 Bean을 정의합니다.
 * 
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@Configuration
public class SimulationConfiguration {
    
    
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
    
    /**
     * 시뮬레이션 실행용 ThreadPoolTaskExecutor
     * 비동기 작업 처리를 위한 스레드 풀
     */
    @Bean(name = "simulationExecutor")
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
     * 스케줄링용 ScheduledExecutorService
     * 주기적인 작업 실행
     */
    @Bean(name = "simulationScheduler", destroyMethod = "shutdown")
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
     * Spring TaskScheduler
     * @Scheduled 어노테이션 지원
     */
    @Bean
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
     * Redis Stream 리스너 컨테이너
     * 실시간 이벤트 스트리밍 처리
     */
    @Bean
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
     * Prometheus 연동 활성화 여부 확인
     */
    private boolean isPrometheusEnabled() {
        // 환경 변수 또는 설정 파일에서 읽어오도록 구현
        String enabled = System.getenv("PROMETHEUS_ENABLED");
        return "true".equalsIgnoreCase(enabled) ||
               "1".equals(enabled);
    }

    /**
     * Grafana 연동 활성화 여부 확인
     */
    private boolean isGrafanaEnabled() {
        // 환경 변수 또는 설정 파일에서 읽어오도록 구현
        String enabled = System.getenv("GRAFANA_ENABLED");
        return "true".equalsIgnoreCase(enabled) ||
               "1".equals(enabled);
    }

    /**
     * 알림 시스템 활성화 여부 확인
     */
    private boolean isAlertingEnabled() {
        // 환경 변수 또는 설정 파일에서 읽어오도록 구현
        String enabled = System.getenv("ALERTING_ENABLED");
        return "true".equalsIgnoreCase(enabled) ||
               "1".equals(enabled);
    }

    /**
     * 시뮬레이션 메트릭 설정
     */
    @Bean
    public SimulationMetricsConfig simulationMetricsConfig() {
        return SimulationMetricsConfig.builder()
            .enableMetrics(true)
            .metricsInterval(5000) // 5초
            .enablePrometheus(isPrometheusEnabled()) // Prometheus 연동 구현
            .enableGrafana(isGrafanaEnabled())    // Grafana 연동 구현
            .build();
    }
    
    /**
     * 시뮬레이션 파라미터 설정
     */
    @Bean
    public SimulationParameters simulationParameters() {
        return SimulationParameters.builder()
            // 공격 생성 파라미터
            .defaultAttackRate(10)      // 분당 10개 공격
            .maxConcurrentAttacks(100)  // 최대 동시 공격 수
            .attackDiversity(0.8)       // 공격 다양성 (0.0-1.0)
            
            // 3-Tier 라우팅 파라미터
            .layer1Threshold(4.0)
            .layer2Threshold(7.0)
            .escalationDelay(2000)      // 2초
            
            // SOAR 파라미터
            .soarApprovalTimeout(60000)  // 60초
            .asyncExecutionEnabled(true)
            .maxPendingApprovals(20)
            
            // 모니터링 파라미터
            .monitoringInterval(5000)    // 5초
            .anomalyDetectionEnabled(true)
            .alertingEnabled(isAlertingEnabled())      // 알림 시스템 연동 구현
            
            .build();
    }
    
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
        // 공격 생성 파라미터
        private int defaultAttackRate;
        private int maxConcurrentAttacks;
        private double attackDiversity;
        
        // 3-Tier 라우팅 파라미터
        private double layer1Threshold;
        private double layer2Threshold;
        private int escalationDelay;
        
        // SOAR 파라미터
        private int soarApprovalTimeout;
        private boolean asyncExecutionEnabled;
        private int maxPendingApprovals;
        
        // 모니터링 파라미터
        private int monitoringInterval;
        private boolean anomalyDetectionEnabled;
        private boolean alertingEnabled;
    }
}