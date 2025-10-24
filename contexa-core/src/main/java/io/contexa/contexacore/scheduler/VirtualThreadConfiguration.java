package io.contexa.contexacore.scheduler;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

/**
 * 최소한의 Virtual Thread 설정
 * application.yml의 spring.threads.virtual.enabled=true로 대부분 해결됨
 *
 * 이 설정은 특별한 Scheduler가 필요한 경우에만 사용
 */
@Configuration
@ConditionalOnProperty(value = "spring.threads.virtual.enabled", havingValue = "true")
@Slf4j
public class VirtualThreadConfiguration {

    /**
     * 수정: 여러 작업을 병렬로 실행하기 위한 'per-task' 스케줄러
     * Lab 병렬 실행과 같이, 서로 다른 독립적인 스트림을 동시에 실행할 때 사용합니다.
     */
    @Bean(name = "parallelVirtualScheduler")
    public Scheduler parallelVirtualScheduler() {
        log.info("병렬 Virtual Thread Scheduler 생성 (named)");
        ThreadFactory virtualThreadFactory = Thread.ofVirtual()
                .name("ParallelLab-VT-", 0)  // prefix + counter (ParallelLab-VT-0, ParallelLab-VT-1, ...)
                .factory();

        ExecutorService executor = Executors.newThreadPerTaskExecutor(virtualThreadFactory);

        return Schedulers.fromExecutorService(executor);
    }

    /**
     * 추가: 단일 스트림 내부의 연속적인 작업을 처리하기 위한 '재사용' 스케줄러
     * publishOn 에서 사용하여, 한 스트림의 모든 청크가 동일한 가상 스레드에서 처리되도록 합니다.
     */
    @Bean(name = "streamingVirtualScheduler")
    public Scheduler streamingVirtualScheduler() {
        log.info("스트리밍 전용 재사용 Virtual Thread Scheduler 생성 (newSingleThreadExecutor)");
        // 가상 스레드를 생성하는 팩토리를 사용하는 단일 스레드 Executor 생성
//        ExecutorService singleVirtualThreadExecutor = Executors.newSingleThreadExecutor(Thread.ofVirtual().factory());
        ExecutorService singleVirtualThreadExecutor = Executors.newSingleThreadExecutor();
        return Schedulers.fromExecutorService(singleVirtualThreadExecutor);
    }
}