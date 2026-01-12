package io.contexa.contexacore.config;

import io.contexa.contexacore.properties.SecurityPlaneProperties;
import lombok.RequiredArgsConstructor;
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
@RequiredArgsConstructor
public class AsyncConfig {

    // AI Native v5.0.0: Properties 클래스 기반 설정 (라이브러리 형태 지원)
    private final SecurityPlaneProperties securityPlaneProperties;

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

    // AI Native v5.0.0: securityEventExecutor 제거
    // - @Async 어노테이션 제거로 더 이상 필요 없음
    // - AuthorizationEventPublisher가 직접 Kafka로 전송 (fire-and-forget)
    // - RequestContextCopyingDecorator도 더 이상 필요 없음 (동기 처리)

    /**
     * LLM 분석 전용 Executor (Throttling)
     *
     * B2B Login Storm 시 LLM 부하를 제어하기 위해 고정된 스레드 수를 사용합니다.
     * 동시 접속이 수천 명이어도 설정된 스레드 수만큼만 순차 처리하여 시스템 안정성을 보장합니다.
     *
     * AI Native v5.0.0: Properties 클래스 기반 설정 (라이브러리 형태 지원)
     * - corePoolSize: LLM 분석 동시 처리 스레드 수 (기본값: 10)
     * - maxPoolSize: 최대 스레드 수 (기본값: 10, 고정 풀 권장)
     * - queueCapacity: 대기 큐 크기 (기본값: 1000)
     *
     * 설정 경로: security.plane.llm-executor.*
     * 확장 가이드: 인스턴스 수 * corePoolSize = 전체 LLM 처리량
     */
    @Bean(name = "llmAnalysisExecutor")
    public Executor llmAnalysisExecutor() {
        SecurityPlaneProperties.LlmExecutorSettings settings = securityPlaneProperties.getLlmExecutor();

        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        // AI Native v5.0.0: Properties 클래스 기반 설정 (라이브러리 형태 지원)
        executor.setCorePoolSize(settings.getCorePoolSize());
        executor.setMaxPoolSize(settings.getMaxPoolSize());
        executor.setQueueCapacity(settings.getQueueCapacity());
        executor.setThreadNamePrefix("LLM-Analysis-");
        // 큐 초과 시 CallerRunsPolicy: 호출 스레드에서 직접 실행 (백프레셔)
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.initialize();
        return executor;
    }
}