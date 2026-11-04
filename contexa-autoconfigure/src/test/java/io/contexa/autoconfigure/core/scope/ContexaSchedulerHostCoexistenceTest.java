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

import io.contexa.autoconfigure.iam.sample.ContexaScheduledSample;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.task.TaskSchedulingAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.SchedulingConfiguration;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/** Contexa's schedules shared the application's scheduler when it turned scheduling on, which Boot sizes at one thread. */
class ContexaSchedulerHostCoexistenceTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(Sample.class)
            .withConfiguration(AutoConfigurations.of(ContexaScopedAnnotationAutoConfiguration.class, TaskSchedulingAutoConfiguration.class));

    @Test
    void contexasSchedulesRunOnContexasPoolWithoutTheApplicationsScheduling() {
        runner.run(context -> assertThat(context.getBean(ContexaScheduledSample.class).threads.poll(5, TimeUnit.SECONDS))
                .startsWith("contexa-scheduling-"));
    }

    @Test
    void contexasSchedulesRunOnContexasPoolWhenTheApplicationTurnsSchedulingOn() {
        runner.withUserConfiguration(ApplicationScheduling.class).run(context -> {
            assertThat(context).hasSingleBean(SchedulingConfiguration.class);
            assertThat(context.getBean(ContexaScheduledSample.class).threads.poll(5, TimeUnit.SECONDS))
                    .startsWith("contexa-scheduling-");
        });
    }

    @Configuration(proxyBeanMethods = false)
    static class Sample {

        @Bean
        ContexaScheduledSample contexaScheduledSample() {
            return new ContexaScheduledSample();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableScheduling
    static class ApplicationScheduling {
    }
}
