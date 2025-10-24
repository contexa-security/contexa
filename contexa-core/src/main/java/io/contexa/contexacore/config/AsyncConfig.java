package io.contexa.contexacore.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * 통합 비동기 실행자 설정
 * 
 * 모든 비동기 작업을 위한 스레드 풀 구성을 통합 관리합니다.
 * AsyncExecutorConfig의 내용을 병합하여 단일 설정 파일로 관리합니다.
 * 
 * @since 3.1.0
 * @author AI Security Framework
 */
@Configuration
public class AsyncConfig {

    @Value("${security.event.executor.core-pool-size:#{T(java.lang.Runtime).getRuntime().availableProcessors() * 2}}")
    private int corePoolSize;

    @Value("${security.event.executor.max-pool-size:#{T(java.lang.Runtime).getRuntime().availableProcessors() * 4}}")
    private int maxPoolSize;

    @Value("${security.event.executor.queue-capacity:10000}")
    private int queueCapacity;
    
    /**
     * 기본 비동기 실행자
     * 일반적인 비동기 작업에 사용
     */
    @Bean(name = "taskExecutor")
    @Primary
    public Executor taskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(5);
        executor.setMaxPoolSize(10);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("Async-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(60);
        executor.initialize();
        return executor;
    }
    
    /**
     * Cold Path 분석용 Executor
     * 백그라운드 심층 분석에 사용
     * ColdPathEventProcessor에서 사용
     */
    @Bean(name = "coldPathExecutor")
    public Executor coldPathExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(5);
        executor.setMaxPoolSize(10);
        executor.setQueueCapacity(200);
        executor.setThreadNamePrefix("ColdPath-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(120);
        executor.initialize();
        return executor;
    }
    
    /**
     * 컨텍스트 관리용 Executor
     * SecurityContext 병렬 처리에 사용
     * 향후 확장을 위해 유지
     */
    @Bean(name = "contextExecutor")
    public Executor contextExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(8);
        executor.setMaxPoolSize(16);
        executor.setQueueCapacity(300);
        executor.setThreadNamePrefix("Context-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(60);
        executor.initialize();
        return executor;
    }
    
    /**
     * SecurityPlane 전용 백그라운드 실행자
     * 24시간 백그라운드 처리를 위한 전용 스레드 풀
     * SecurityPlaneAgent의 백그라운드 태스크에 사용
     */
    @Bean(name = "securityPlaneExecutor")
    public Executor securityPlaneExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(3);
        executor.setMaxPoolSize(5);
        executor.setQueueCapacity(1000);
        executor.setThreadNamePrefix("SecurityPlane-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(300); // 5분 대기
        executor.initialize();
        return executor;
    }

    /**
     * Security Event 발행 전용 Executor
     *
     * ZeroTrustEventListener, AuthorizationEventPublisher 등에서 사용
     * Event Storm 방지를 위한 전용 스레드 풀
     *
     * 설계 원칙:
     * - 높은 처리량: CorePoolSize=10 (이벤트 발행 전용)
     * - Peak 대응: MaxPoolSize=20 (피크 시간 대응)
     * - Event Storm 버퍼: QueueCapacity=5000 (대량 이벤트 버퍼링)
     * - Fail-Safe: CallerRunsPolicy (큐 초과 시 호출 스레드에서 실행)
     *
     * 수백만 사용자 시뮬레이션:
     * - 11,574 TPS → 샘플링 후 3,357 TPS
     * - 10 Core + 20 Max = 최대 30 스레드
     * - 3,357 TPS ÷ 30 = 112 TPS/스레드 (충분한 여유)
     *
     * @since 3.2.0
     */
    /**
     * 보안 이벤트 비동기 처리를 위한 전용 Executor
     *
     * 수백만 사용자의 이벤트를 처리하기 위해 최적화된 스레드 풀 구성
     * Zero Trust 보안 모델을 위해 모든 인증 이벤트를 실시간 분석합니다.
     */
    @Bean(name = "securityEventExecutor")
    public Executor securityEventExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();

        // 코어 스레드 수: CPU 코어의 2배 (설정값 기본값 사용)
        executor.setCorePoolSize(corePoolSize);

        // 최대 스레드 수: CPU 코어의 4배 (설정값 기본값 사용)
        executor.setMaxPoolSize(maxPoolSize);

        // 큐 용량: 10,000개 이벤트 버퍼링 (설정값 기본값 사용)
        executor.setQueueCapacity(queueCapacity);

        // 스레드 이름 프리픽스
        executor.setThreadNamePrefix("SecurityEvent-");

        // 큐가 가득 찼을 때 정책: 호출자 스레드에서 실행
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());

        // 유휴 스레드 유지 시간: 60초
        executor.setKeepAliveSeconds(60);

        // 종료 시 태스크 완료 대기
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(30);

        executor.initialize();

        return executor;
    }
}