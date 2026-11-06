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
package io.contexa.contexacommon.config.redis;

import io.contexa.contexacommon.store.ApplicationNamespace;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * An application that shares its Redis and its Kafka with another is told apart by {@code spring.application.name}; one
 * without a name is told, once, at INFO, in the distributed mode, which is the only mode that keeps its state there.
 */
@ExtendWith(OutputCaptureExtension.class)
class ApplicationNamespaceNoticeTest {

    private static final String NOTICE = "spring.application.name is not set";

    private ApplicationContextRunner runner(String... properties) {
        return new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(RedisAutoConfiguration.class, CommonRedisAutoConfiguration.class))
                .withPropertyValues(properties);
    }

    @Test
    @DisplayName("an application without a name, in the distributed mode, is told once at INFO and starts")
    void anUnnamedApplicationIsToldOnce(CapturedOutput output) {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            runner("contexa.infrastructure.mode=distributed", "spring.data.redis.host=127.0.0.1")
                    .run(context -> assertThat(context).hasNotFailed());
        }

        assertThat(output).contains(NOTICE).contains("INFO").contains("shared with another application");
        assertThat(output.toString().split(NOTICE, -1)).as("said once").hasSize(2);
    }

    @Test
    @DisplayName("an application with a name is told nothing at INFO")
    void aNamedApplicationIsToldNothing(CapturedOutput output) {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            runner("contexa.infrastructure.mode=distributed", "spring.data.redis.host=127.0.0.1")
                    .run(context -> assertThat(context).hasNotFailed());
        }

        assertThat(output).doesNotContain(NOTICE);
    }

    @Test
    @DisplayName("outside the distributed mode nothing is said: Contexa keeps its state in memory")
    void outsideTheDistributedModeNothingIsSaid(CapturedOutput output) {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            runner("spring.data.redis.host=127.0.0.1").run(context -> assertThat(context).hasNotFailed());
        }

        assertThat(output).doesNotContain(NOTICE);
    }
}
