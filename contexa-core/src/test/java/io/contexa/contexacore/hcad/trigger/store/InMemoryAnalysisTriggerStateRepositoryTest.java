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
package io.contexa.contexacore.hcad.trigger.store;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryAnalysisTriggerStateRepositoryTest {

    @Test
    @DisplayName("rate limit window should allow up to the configured count")
    void tryAcquireRateLimit_shouldRespectConfiguredWindowLimit() {
        InMemoryAnalysisTriggerStateRepository repository = new InMemoryAnalysisTriggerStateRepository();

        assertThat(repository.tryAcquireRateLimit("global", Duration.ofSeconds(60), 2)).isTrue();
        assertThat(repository.tryAcquireRateLimit("global", Duration.ofSeconds(60), 2)).isTrue();
        assertThat(repository.tryAcquireRateLimit("global", Duration.ofSeconds(60), 2)).isFalse();
        assertThat(repository.tryAcquireRateLimit("other", Duration.ofSeconds(60), 2)).isTrue();
    }

    @Test
    @DisplayName("invalid rate limit settings should deny acquisition")
    void tryAcquireRateLimit_invalidSettings_shouldDeny() {
        InMemoryAnalysisTriggerStateRepository repository = new InMemoryAnalysisTriggerStateRepository();

        assertThat(repository.tryAcquireRateLimit("global", Duration.ZERO, 2)).isFalse();
        assertThat(repository.tryAcquireRateLimit("global", Duration.ofSeconds(60), 0)).isFalse();
        assertThat(repository.tryAcquireRateLimit(null, Duration.ofSeconds(60), 2)).isFalse();
    }
}
