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
 * Q-25: Redis Cluster is out of this release. Contexa's final decision writes use multi-key scripts without hash tags, so
 * a cluster may refuse them. The application starts all the same, and the start says so at ERROR.
 */
@ExtendWith(OutputCaptureExtension.class)
class RedisClusterNoticeTest {

    private static final String NOTICE = "Redis Cluster is not supported";

    private ApplicationContextRunner runner(String... properties) {
        return new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(RedisAutoConfiguration.class, CommonRedisAutoConfiguration.class))
                .withPropertyValues(properties);
    }

    @Test
    @DisplayName("a cluster in the distributed mode is named at ERROR, and the application starts")
    void aClusterIsNamedAndTheApplicationStarts(CapturedOutput output) {
        runner("contexa.infrastructure.mode=distributed", "spring.data.redis.cluster.nodes=127.0.0.1:7000,127.0.0.1:7001")
                .run(context -> assertThat(context).hasNotFailed());

        assertThat(output).contains(NOTICE).contains("ERROR").contains("Sentinel");
    }

    @Test
    @DisplayName("a single server says nothing")
    void aSingleServerSaysNothing(CapturedOutput output) {
        runner("contexa.infrastructure.mode=distributed", "spring.data.redis.host=127.0.0.1")
                .run(context -> assertThat(context).hasNotFailed());

        assertThat(output).doesNotContain(NOTICE);
    }

    @Test
    @DisplayName("Sentinel says nothing")
    void sentinelSaysNothing(CapturedOutput output) {
        runner("contexa.infrastructure.mode=distributed", "spring.data.redis.sentinel.master=main",
                "spring.data.redis.sentinel.nodes=127.0.0.1:26379")
                .run(context -> assertThat(context).hasNotFailed());

        assertThat(output).doesNotContain(NOTICE);
    }

    @Test
    @DisplayName("an application's own cluster says nothing while Contexa keeps its state in memory")
    void anApplicationsClusterOutsideTheDistributedModeSaysNothing(CapturedOutput output) {
        runner("spring.data.redis.cluster.nodes=127.0.0.1:7000,127.0.0.1:7001")
                .run(context -> assertThat(context).hasNotFailed());

        assertThat(output).doesNotContain(NOTICE);
    }
}
