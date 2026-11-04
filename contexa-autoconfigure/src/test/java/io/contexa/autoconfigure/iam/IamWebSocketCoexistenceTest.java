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
package io.contexa.autoconfigure.iam;

import io.contexa.contexaiam.aiam.config.WebSocketConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.task.TaskExecutionAutoConfiguration;
import org.springframework.boot.autoconfigure.task.TaskSchedulingAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * The message broker Contexa brings for its console does not take the place of what the application, or Spring Boot for it, uses: the
 * executor a bean asks for by type is the application's default executor, and the tasks the application scheduled run on Spring Boot's
 * scheduler, not on the threads of the broker.
 */
@ExtendWith(OutputCaptureExtension.class)
class IamWebSocketCoexistenceTest {

    private WebApplicationContextRunner runner(Class<?>... application) {
        return new WebApplicationContextRunner()
                .withUserConfiguration(application)
                .withUserConfiguration(WebSocketConfig.class)
                .withConfiguration(AutoConfigurations.of(TaskExecutionAutoConfiguration.class, TaskSchedulingAutoConfiguration.class));
    }

    @Test
    void theExecutorAnApplicationBeanAsksForByTypeIsSpringBootsDefaultOne() {
        runner(Application.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).as("Spring Boot still makes the application's default executor").hasBean("applicationTaskExecutor");

            ExecutorConsumer consumer = context.getBean(ExecutorConsumer.class);
            assertThat(consumer.executor()).as("an Executor asked for by type").isSameAs(context.getBean("applicationTaskExecutor"));
            assertThat(consumer.taskExecutor()).as("a TaskExecutor asked for by type").isSameAs(context.getBean("applicationTaskExecutor"));
        });
    }

    @Test
    void theApplicationsScheduledTasksRunOnSpringBootsSchedulerNotOnTheBroker() {
        runner(Scheduling.class).run(context -> {
            assertThat(context).hasNotFailed();
            Thread.sleep(400);

            Set<String> threads = context.getBean(Ticker.class).threads;
            assertThat(threads).isNotEmpty();
            assertThat(threads).as("threads that ran the application's @Scheduled").allSatisfy(name -> assertThat(name).startsWith("scheduling-"));
            assertThat(context.getBeanProvider(TaskScheduler.class).orderedStream().toList())
                    .as("Spring Boot's scheduler is the one asked for by type").contains(context.getBean("taskScheduler", TaskScheduler.class));
        });
    }

    @Test
    void theBrokersOwnWiringStillFindsItsExecutorsAndScheduler() {
        runner(Application.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean("clientInboundChannelExecutor")).isInstanceOf(TaskExecutor.class);
            assertThat(context.getBean("clientOutboundChannelExecutor")).isInstanceOf(TaskExecutor.class);
            assertThat(context.getBean("brokerChannelExecutor")).isInstanceOf(Executor.class);
            assertThat(context.getBean("messageBrokerTaskScheduler")).isInstanceOf(TaskScheduler.class);
            assertThat(context.getBean("messageBrokerSockJsTaskScheduler")).as("the alias Spring gives the same scheduler")
                    .isSameAs(context.getBean("messageBrokerTaskScheduler"));
            assertThat(context.containsBean("webSocketMessageBrokerStats")).isTrue();
            assertThat(context.containsBean("clientInboundChannel")).isTrue();
        });
    }

    private WebApplicationContextRunner autoConfigured(Class<?> application) {
        return new WebApplicationContextRunner()
                .withUserConfiguration(application, Platform.class)
                .withConfiguration(AutoConfigurations.of(IamWebSocketAutoConfiguration.class));
    }

    @Test
    void contexasBrokerIsThereWhenTheApplicationHasNothingOfTheKind() {
        autoConfigured(ApplicationWithNothingOfTheKind.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasBean("clientInboundChannel").hasBean("userRegistry");
        });
    }

    @Test
    void aBeanOfTheApplicationNamedLikeOneOfTheBrokersMakesContexasBrokerStandAsideAndSaysSo(CapturedOutput output) {
        autoConfigured(ApplicationWithItsOwnUserRegistry.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean("userRegistry")).as("the application's own bean of that name").isEqualTo("the application's registry");
            assertThat(context).as("no broker of Contexa's in an application that uses the name").doesNotHaveBean("clientInboundChannel");
            assertThat(output).as("never silently").contains("/ws-soar", "userRegistry", "contexa.iam.websocket.enabled=false");
        });
    }

    @Test
    void switchingTheConsoleWebSocketOffIsQuiet(CapturedOutput output) {
        autoConfigured(ApplicationWithItsOwnUserRegistry.class).withPropertyValues("contexa.iam.websocket.enabled=false").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean("clientInboundChannel");
            assertThat(output).doesNotContain("console WebSocket (/ws-soar) is not started");
        });
    }

    @Configuration(proxyBeanMethods = false)
    static class Platform {
        @Bean
        PlatformConfig platformConfig() {
            return mock(PlatformConfig.class);
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class ApplicationWithNothingOfTheKind {
    }

    @Configuration(proxyBeanMethods = false)
    static class ApplicationWithItsOwnUserRegistry {
        @Bean
        String userRegistry() {
            return "the application's registry";
        }
    }

    public static class ExecutorConsumer {

        private final Executor executor;
        private final TaskExecutor taskExecutor;

        ExecutorConsumer(Executor executor, TaskExecutor taskExecutor) {
            this.executor = executor;
            this.taskExecutor = taskExecutor;
        }

        Executor executor() {
            return executor;
        }

        TaskExecutor taskExecutor() {
            return taskExecutor;
        }
    }

    public static class Ticker {

        final Set<String> threads = ConcurrentHashMap.newKeySet();

        @Scheduled(fixedRate = 50)
        public void tick() {
            threads.add(Thread.currentThread().getName());
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class Application {
        @Bean
        ExecutorConsumer executorConsumer(Executor executor, TaskExecutor taskExecutor) {
            return new ExecutorConsumer(executor, taskExecutor);
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableScheduling
    static class Scheduling {
        @Bean
        Ticker ticker() {
            return new Ticker();
        }
    }
}
