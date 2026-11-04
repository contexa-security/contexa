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
package io.contexa.autoconfigure.core.scope;

import com.legacyshop.scope.LegacyScopeApplication;
import io.contexa.autoconfigure.core.ContexaProxyModeAutoConfiguration;
import io.contexa.autoconfigure.core.scope.sample.ContexaSample;
import org.junit.jupiter.api.Test;
import org.springframework.aop.framework.Advised;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.aop.AopAutoConfiguration;
import org.springframework.boot.autoconfigure.cache.CacheAutoConfiguration;
import org.springframework.boot.autoconfigure.task.TaskExecutionAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.interceptor.BeanFactoryCacheOperationSourceAdvisor;
import org.springframework.scheduling.annotation.AsyncAnnotationAdvisor;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.config.ScheduledTaskHolder;

import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The order of auto-configurations is not Contexa's to choose. When something that comes after Contexa's auto-configuration switches the
 * same support on (a library's auto-configuration, say), both Contexa's processor and the other one are in the context. Contexa's must
 * then leave its beans to the other, so that a {@code @Scheduled} method of Contexa does not run twice and a cached or asynchronous
 * method is not advised twice.
 */
class ContexaScopedOrderTest {

    /** Comes after Contexa's auto-configuration and switches the supports on, as a library's auto-configuration might. */
    @AutoConfiguration(after = ContexaScopedAnnotationAutoConfiguration.class)
    @EnableScheduling
    @EnableAsync
    @EnableCaching
    static class LaterAutoConfiguration {
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(LegacyScopeApplication.Dormant.class, ContexaSample.Definition.class)
            .withConfiguration(AutoConfigurations.of(AopAutoConfiguration.class, CacheAutoConfiguration.class,
                    TaskExecutionAutoConfiguration.class, ContexaProxyModeAutoConfiguration.class,
                    ContexaScopedAnnotationAutoConfiguration.class, LaterAutoConfiguration.class));

    private static long advisorsOf(Object bean, Class<?> type) {
        return Arrays.stream(((Advised) bean).getAdvisors()).filter(type::isInstance).count();
    }

    @Test
    void bothProcessorsAreInTheContextButContexasBeanIsAdvisedOnce() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).as("Contexa's was evaluated first and is there").hasBean("contexaAsyncAnnotationProcessor");
            assertThat(context).as("and so is the one that came after")
                    .hasBean("org.springframework.context.annotation.internalAsyncAnnotationProcessor");
            Object sample = context.getBean(ContexaSample.class);

            assertThat(advisorsOf(sample, AsyncAnnotationAdvisor.class)).as("asynchronous execution advising Contexa's bean").isEqualTo(1);
            assertThat(advisorsOf(sample, BeanFactoryCacheOperationSourceAdvisor.class)).as("caching advising Contexa's bean").isEqualTo(1);
        });
    }

    @Test
    void aScheduledMethodOfContexaIsScheduledOnce() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            long tasks = context.getBeansOfType(ScheduledTaskHolder.class).values().stream()
                    .flatMap(holder -> holder.getScheduledTasks().stream())
                    .filter(task -> String.valueOf(task.getTask()).contains(ContexaSample.class.getName() + ".tick"))
                    .count();

            assertThat(tasks).as("scheduled tasks of Contexa's sample, whichever processor holds them: it has one method").isEqualTo(1);
        });
    }

    @Test
    void supportOfAParentContextDoesNotServeTheBeansOfAChildContext() {
        // A processor serves the beans of its own context only; an application's support in the parent must not make Contexa's stand aside.
        new ApplicationContextRunner().withUserConfiguration(LegacyScopeApplication.Enabled.class)
                .withConfiguration(AutoConfigurations.of(AopAutoConfiguration.class, TaskExecutionAutoConfiguration.class))
                .run(parent -> {
                    assertThat(parent).hasNotFailed();
                    new ApplicationContextRunner()
                            .withUserConfiguration(LegacyScopeApplication.Dormant.class, ContexaSample.Definition.class)
                            .withConfiguration(AutoConfigurations.of(AopAutoConfiguration.class, CacheAutoConfiguration.class,
                                    TaskExecutionAutoConfiguration.class, ContexaProxyModeAutoConfiguration.class,
                                    ContexaScopedAnnotationAutoConfiguration.class))
                            .withParent(parent).run(child -> {
                        assertThat(child).hasNotFailed();
                        ContexaSample sample = child.getBean(ContexaSample.class);

                        assertThat(sample.thread().get(2, TimeUnit.SECONDS)).as("@Async of Contexa in the child context")
                                .startsWith("contexa-async-");
                        Thread.sleep(300);
                        assertThat(sample.ticks()).as("@Scheduled of Contexa in the child context").isGreaterThan(1);
                    });
                });
    }

    @Test
    void contexasAnnotationsStillWorkUnderTheOtherProcessors() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            ContexaSample sample = context.getBean(ContexaSample.class);

            sample.cached("a");
            sample.cached("a");
            assertThat(sample.cacheCalls()).as("cached by the processor that came after, with Contexa's cache manager").isEqualTo(1);
            assertThat(sample.thread().get(2, TimeUnit.SECONDS)).startsWith("contexa-async-");
        });
    }
}
