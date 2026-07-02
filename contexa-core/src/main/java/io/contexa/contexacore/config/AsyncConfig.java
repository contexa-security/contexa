/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.config;

import io.contexa.contexacore.autonomous.LlmAnalysisBackpressureMonitor;
import io.contexa.contexacore.properties.HcadProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;

@Configuration
@RequiredArgsConstructor
public class AsyncConfig {

    private final SecurityPlaneProperties securityPlaneProperties;

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

    @Bean(name = "securityPlaneExecutor")
    public Executor securityPlaneExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(3);
        executor.setMaxPoolSize(5);
        executor.setQueueCapacity(1000);
        executor.setThreadNamePrefix("SecurityPlane-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(300); 
        executor.initialize();
        return executor;
    }

    @Bean(name = "llmAnalysisExecutor")
    public ThreadPoolTaskExecutor llmAnalysisExecutor() {
        SecurityPlaneProperties.LlmExecutorSettings settings = securityPlaneProperties.getLlmExecutor();

        ScalingThreadPoolTaskExecutor executor = new ScalingThreadPoolTaskExecutor();
        
        int corePoolSize = Math.max(1, settings.getCorePoolSize());
        int maxPoolSize = Math.max(corePoolSize, settings.getMaxPoolSize());
        int queueCapacity = Math.max(0, settings.getQueueCapacity());

        executor.setCorePoolSize(corePoolSize);
        executor.setMaxPoolSize(maxPoolSize);
        executor.setQueueCapacity(queueCapacity);
        executor.setThreadNamePrefix("LLM-Analysis-");

        executor.setRejectedExecutionHandler(new BlockingQueueRejectedExecutionHandler());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.initialize();
        if (settings.isPrestartCoreThreads()) {
            executor.getThreadPoolExecutor().prestartAllCoreThreads();
        }
        return executor;
    }


    @Bean
    public LlmAnalysisBackpressureMonitor llmAnalysisBackpressureMonitor(
            @Qualifier("llmAnalysisExecutor") ThreadPoolTaskExecutor llmAnalysisExecutor,
            ObjectProvider<HcadProperties> hcadPropertiesProvider) {
        return new LlmAnalysisBackpressureMonitor(
                llmAnalysisExecutor,
                securityPlaneProperties,
                hcadPropertiesProvider.getIfAvailable());
    }

    private static final class BlockingQueueRejectedExecutionHandler implements RejectedExecutionHandler {

        @Override
        public void rejectedExecution(Runnable runnable, ThreadPoolExecutor executor) {
            if (executor == null || executor.isShutdown()) {
                throw new RejectedExecutionException("LLM analysis executor is shut down");
            }
            try {
                executor.getQueue().put(runnable);
            } catch (InterruptedException interruptedException) {
                Thread.currentThread().interrupt();
                throw new RejectedExecutionException("Interrupted while waiting for LLM analysis queue capacity", interruptedException);
            }
        }
    }
    private static final class ScalingThreadPoolTaskExecutor extends ThreadPoolTaskExecutor {

        private ScalingQueue scalingQueue;

        @Override
        protected BlockingQueue<Runnable> createQueue(int queueCapacity) {
            if (queueCapacity > 0) {
                this.scalingQueue = new ScalingQueue(queueCapacity);
                return this.scalingQueue;
            }
            return super.createQueue(queueCapacity);
        }

        @Override
        protected ExecutorService initializeExecutor(
                ThreadFactory threadFactory,
                RejectedExecutionHandler rejectedExecutionHandler) {
            ExecutorService executorService = super.initializeExecutor(threadFactory, rejectedExecutionHandler);
            if (this.scalingQueue != null) {
                this.scalingQueue.setExecutor(getThreadPoolExecutor());
            }
            return executorService;
        }
    }

    private static final class ScalingQueue extends LinkedBlockingQueue<Runnable> {

        private transient ThreadPoolExecutor executor;

        private ScalingQueue(int capacity) {
            super(capacity);
        }

        private void setExecutor(ThreadPoolExecutor executor) {
            this.executor = executor;
        }

        @Override
        public boolean offer(Runnable runnable) {
            ThreadPoolExecutor currentExecutor = this.executor;
            if (currentExecutor == null) {
                return super.offer(runnable);
            }
            if (currentExecutor.getPoolSize() < currentExecutor.getMaximumPoolSize()
                    && currentExecutor.getActiveCount() >= currentExecutor.getPoolSize()) {
                return false;
            }
            return super.offer(runnable);
        }
    }
    @Bean(name = "saasForwardingExecutor")
    public Executor saasForwardingExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(4);
        executor.setQueueCapacity(500);
        executor.setThreadNamePrefix("SaaS-Forwarding-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(120);
        executor.initialize();
        return executor;
    }
}

