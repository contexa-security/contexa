package io.contexa.contexaidentity.security.statemachine.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.aop.interceptor.AsyncUncaughtExceptionHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.AsyncConfigurer;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * 비동기 이벤트 처리를 위한 설정
 * @Async 어노테이션 활성화 및 Executor 설정
 */
@Slf4j
@Configuration
@EnableAsync
public class AsyncEventConfiguration implements AsyncConfigurer {

    /**
     * MFA 이벤트 처리용 Executor
     */
    @Bean(name = "mfaEventExecutor")
    public Executor mfaEventExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();

        // 스레드 풀 설정
        executor.setCorePoolSize(10);
        executor.setMaxPoolSize(50);
        executor.setQueueCapacity(1000);
        executor.setThreadNamePrefix("mfa-event-");

        // 거부 정책: 호출자 스레드에서 실행
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());

        // 종료 시 작업 완료 대기
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(30);

        executor.initialize();

        log.info("MFA Event Executor initialized - Core: {}, Max: {}, Queue: {}",
                executor.getCorePoolSize(),
                executor.getMaxPoolSize(),
                executor.getQueueCapacity());

        return executor;
    }

    /**
     * 기본 비동기 Executor
     * @Async 어노테이션에서 executor를 지정하지 않은 경우 사용
     */
    @Override
    public Executor getAsyncExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();

        executor.setCorePoolSize(5);
        executor.setMaxPoolSize(20);
        executor.setQueueCapacity(500);
        executor.setThreadNamePrefix("async-default-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(30);
        executor.initialize();

        return executor;
    }

    /**
     * 비동기 예외 핸들러
     */
    @Override
    public AsyncUncaughtExceptionHandler getAsyncUncaughtExceptionHandler() {
        return (throwable, method, objects) -> {
            log.error("Async execution error in method: {} with params: {}",
                    method.getName(), objects, throwable);

            // 메트릭 수집 또는 알림 전송
            handleAsyncError(throwable, method.getName());
        };
    }

    /**
     * 비동기 에러 처리
     */
    private void handleAsyncError(Throwable throwable, String methodName) {
        // 에러 타입별 처리
        if (throwable instanceof SecurityException) {
            log.error("Security error in async method {}: {}",
                    methodName, throwable.getMessage());
            // 보안 알림 전송
        } else if (throwable instanceof IllegalStateException) {
            log.error("State error in async method {}: {}",
                    methodName, throwable.getMessage());
            // 상태 불일치 알림
        } else {
            log.error("Unexpected error in async method {}: {}",
                    methodName, throwable.getMessage());
        }
    }

    /**
     * 모니터링용 Executor (별도 스레드 풀)
     */
    @Bean(name = "monitoringExecutor")
    public Executor monitoringExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();

        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(5);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("monitoring-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.DiscardPolicy());
        executor.initialize();

        return executor;
    }
}
