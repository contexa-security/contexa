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


@Configuration
@ConditionalOnProperty(value = "spring.threads.virtual.enabled", havingValue = "true")
@Slf4j
public class VirtualThreadConfiguration {

    
    @Bean(name = "parallelVirtualScheduler")
    public Scheduler parallelVirtualScheduler() {
        log.info("병렬 Virtual Thread Scheduler 생성 (named)");
        ThreadFactory virtualThreadFactory = Thread.ofVirtual()
                .name("ParallelLab-VT-", 0)  
                .factory();

        ExecutorService executor = Executors.newThreadPerTaskExecutor(virtualThreadFactory);

        return Schedulers.fromExecutorService(executor);
    }

    
    @Bean(name = "streamingVirtualScheduler")
    public Scheduler streamingVirtualScheduler() {
        log.info("스트리밍 전용 재사용 Virtual Thread Scheduler 생성 (newSingleThreadExecutor)");
        

        ExecutorService singleVirtualThreadExecutor = Executors.newSingleThreadExecutor();
        return Schedulers.fromExecutorService(singleVirtualThreadExecutor);
    }
}