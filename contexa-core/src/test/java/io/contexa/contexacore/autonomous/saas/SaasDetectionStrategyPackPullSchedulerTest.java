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
package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.MapPropertySource;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.ScheduledAnnotationBeanPostProcessor;
import org.springframework.scheduling.config.FixedDelayTask;
import org.springframework.scheduling.config.ScheduledTask;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;

class SaasDetectionStrategyPackPullSchedulerTest {

    @Test
    void schedulerShouldStartWithDetectionStrategyPullProperties() {
        try (AnnotationConfigApplicationContext context = schedulingContext(Map.of(
                "contexa.saas.detection-strategy.initial-delay-ms", "600000",
                "contexa.saas.detection-strategy.pull-interval-ms", "900000"))) {

            assertThatCode(context::refresh).doesNotThrowAnyException();

            FixedDelayTask task = registeredFixedDelayTask(context);
            assertThat(task.getInitialDelayDuration()).isEqualTo(Duration.ofMillis(600_000L));
            assertThat(task.getIntervalDuration()).isEqualTo(Duration.ofMillis(900_000L));
        }
    }

    @Test
    void schedulerShouldStartWithDefaultDetectionStrategyPullInterval() {
        try (AnnotationConfigApplicationContext context = schedulingContext(Map.of())) {

            assertThatCode(context::refresh).doesNotThrowAnyException();

            FixedDelayTask task = registeredFixedDelayTask(context);
            assertThat(task.getInitialDelayDuration()).isEqualTo(Duration.ZERO);
            assertThat(task.getIntervalDuration()).isEqualTo(Duration.ofMillis(3_600_000L));
        }
    }

    private AnnotationConfigApplicationContext schedulingContext(Map<String, Object> properties) {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("schedulerTest", properties));
        context.register(SchedulingEnabledConfiguration.class);
        context.registerBean(SaasDetectionStrategyPackPullScheduler.class,
                () -> new SaasDetectionStrategyPackPullScheduler(
                        mock(SaasDetectionStrategyPackService.class),
                        SaasForwardingProperties.builder().enabled(false).build()));
        return context;
    }

    private FixedDelayTask registeredFixedDelayTask(AnnotationConfigApplicationContext context) {
        return context.getBean(ScheduledAnnotationBeanPostProcessor.class).getScheduledTasks().stream()
                .map(ScheduledTask::getTask)
                .filter(FixedDelayTask.class::isInstance)
                .map(FixedDelayTask.class::cast)
                .findFirst()
                .orElseThrow(() -> new AssertionError("No fixed-delay task was registered"));
    }

    @Configuration(proxyBeanMethods = false)
    @EnableScheduling
    static class SchedulingEnabledConfiguration {
    }
}
