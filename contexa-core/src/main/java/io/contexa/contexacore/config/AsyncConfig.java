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

import io.contexa.contexacommon.store.ContexaWorkCallerRunsPolicy;
import io.contexa.contexacore.autonomous.AnalysisTurn;
import io.contexa.contexacore.autonomous.LlmAnalysisBackpressureMonitor;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;

@Configuration
@RequiredArgsConstructor
public class AsyncConfig {

    private final SecurityPlaneProperties securityPlaneProperties;

    @Bean(name = "contexaTaskExecutor", defaultCandidate = false)
    public Executor taskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(5);
        executor.setMaxPoolSize(10);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("contexa-async-");
        executor.setAllowCoreThreadTimeOut(true);
        executor.setRejectedExecutionHandler(new ContexaWorkCallerRunsPolicy());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(60);
        executor.initialize();
        return executor;
    }

    @Bean(name = "contexaColdPathExecutor", defaultCandidate = false)
    public Executor coldPathExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(5);
        executor.setMaxPoolSize(10);
        executor.setQueueCapacity(200);
        executor.setThreadNamePrefix("contexa-cold-path-");
        executor.setAllowCoreThreadTimeOut(true);
        executor.setRejectedExecutionHandler(new ContexaWorkCallerRunsPolicy());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(120);
        executor.initialize();
        return executor;
    }

    @Bean(name = "contexaContextExecutor", defaultCandidate = false)
    public Executor contextExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(8);
        executor.setMaxPoolSize(16);
        executor.setQueueCapacity(300);
        executor.setThreadNamePrefix("contexa-context-");
        executor.setAllowCoreThreadTimeOut(true);
        executor.setRejectedExecutionHandler(new ContexaWorkCallerRunsPolicy());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(60);
        executor.initialize();
        return executor;
    }

    @Bean(name = "contexaSecurityPlaneExecutor", defaultCandidate = false)
    public Executor securityPlaneExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(3);
        executor.setMaxPoolSize(5);
        executor.setQueueCapacity(1000);
        executor.setThreadNamePrefix("contexa-security-plane-");
        executor.setAllowCoreThreadTimeOut(true);
        executor.setRejectedExecutionHandler(new ContexaWorkCallerRunsPolicy());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(300); 
        executor.initialize();
        return executor;
    }

    @Bean(name = "contexaLlmAnalysisExecutor", defaultCandidate = false)
    public ThreadPoolTaskExecutor llmAnalysisExecutor() {
        SecurityPlaneProperties.LlmExecutorSettings settings = securityPlaneProperties.getLlmExecutor();

        ScalingThreadPoolTaskExecutor executor = new ScalingThreadPoolTaskExecutor();
        
        int corePoolSize = Math.max(1, settings.getCorePoolSize());
        int maxPoolSize = Math.max(corePoolSize, settings.getMaxPoolSize());
        int queueCapacity = Math.max(0, settings.getQueueCapacity());

        executor.setCorePoolSize(corePoolSize);
        executor.setMaxPoolSize(maxPoolSize);
        executor.setQueueCapacity(queueCapacity);
        executor.setThreadNamePrefix("contexa-llm-analysis-");
        executor.setAllowCoreThreadTimeOut(true);

        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.AbortPolicy());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        // Not initialized here: Spring does it in afterPropertiesSet, and a pool started here would be replaced by a second one,
        // its prestarted threads (not daemons) owned by nobody and holding the JVM after a failed start-up.
        executor.setPrestartCoreThreads(settings.isPrestartCoreThreads());
        return executor;
    }


    @Bean(name = "contexaLlmAnalysisBackpressureMonitor")
    public LlmAnalysisBackpressureMonitor llmAnalysisBackpressureMonitor(
            @Qualifier("contexaLlmAnalysisExecutor") ThreadPoolTaskExecutor contexaLlmAnalysisExecutor) {
        return new LlmAnalysisBackpressureMonitor(
                contexaLlmAnalysisExecutor,
                securityPlaneProperties);
    }

    private static final class ScalingThreadPoolTaskExecutor extends ThreadPoolTaskExecutor {

        private ScalingQueue scalingQueue;

        private boolean prestartCoreThreads;

        private void setPrestartCoreThreads(boolean prestartCoreThreads) {
            this.prestartCoreThreads = prestartCoreThreads;
        }

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
            if (this.prestartCoreThreads) {
                getThreadPoolExecutor().prestartAllCoreThreads();
            }
            return executorService;
        }
    }

    /** Q-23: a bounded line in the order of {@link AnalysisTurn}; the pool grows to its maximum before anyone waits. */
    private static final class ScalingQueue extends PriorityBlockingQueue<Runnable> {

        private static final int INITIAL_LINE_SIZE = 64;

        private final int capacity;
        private transient ThreadPoolExecutor executor;

        private ScalingQueue(int capacity) {
            super(INITIAL_LINE_SIZE, AnalysisTurn.ORDER);
            this.capacity = capacity;
        }

        private void setExecutor(ThreadPoolExecutor executor) {
            this.executor = executor;
        }

        @Override
        public boolean offer(Runnable runnable) {
            ThreadPoolExecutor currentExecutor = this.executor;
            if (currentExecutor != null
                    && currentExecutor.getPoolSize() < currentExecutor.getMaximumPoolSize()
                    && currentExecutor.getActiveCount() >= currentExecutor.getPoolSize()) {
                return false;
            }
            return size() < capacity && super.offer(runnable);
        }

        @Override
        public int remainingCapacity() {
            return Math.max(0, capacity - size());
        }
    }
    @Bean(name = "contexaSaasForwardingExecutor", defaultCandidate = false)
    public Executor saasForwardingExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(4);
        executor.setQueueCapacity(500);
        executor.setThreadNamePrefix("contexa-saas-forwarding-");
        executor.setAllowCoreThreadTimeOut(true);
        executor.setRejectedExecutionHandler(new ContexaWorkCallerRunsPolicy());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(120);
        executor.initialize();
        return executor;
    }
}

