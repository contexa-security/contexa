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
package io.contexa.contexacore.autonomous.repository;

import org.awaitility.Awaitility;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

abstract class AbstractZeroTrustActionRepositoryFailCountContractTest {

    protected ZeroTrustActionRepository repository;

    protected abstract ZeroTrustActionRepository createRepository();

    protected abstract ZeroTrustActionRepository createRepositoryWithFailCountTtl(Duration failCountTtl);

    @BeforeEach
    void setUpRepository() {
        repository = createRepository();
    }

    @Test
    @DisplayName("getBlockMfaFailCount returns zero for unknown user")
    void failCount_unknown_returnsZero() {
        assertThat(repository.getBlockMfaFailCount("ghost")).isZero();
    }

    @Test
    @DisplayName("incrementBlockMfaFailCount accumulates the count")
    void failCount_incrementsAccumulate() {
        repository.incrementBlockMfaFailCount("u-inc");
        repository.incrementBlockMfaFailCount("u-inc");
        repository.incrementBlockMfaFailCount("u-inc");

        assertThat(repository.getBlockMfaFailCount("u-inc")).isEqualTo(3L);
    }

    @Test
    @DisplayName("Fail count is zero after the configured TTL expires")
    void failCount_expiresAfterTtl() {
        ZeroTrustActionRepository ttlRepository = createRepositoryWithFailCountTtl(Duration.ofMillis(500));
        ttlRepository.incrementBlockMfaFailCount("u-ttl");
        ttlRepository.incrementBlockMfaFailCount("u-ttl");

        assertThat(ttlRepository.getBlockMfaFailCount("u-ttl"))
                .as("count must be visible right after increment")
                .isEqualTo(2L);

        Awaitility.await()
                .atMost(Duration.ofSeconds(5))
                .pollInterval(Duration.ofMillis(100))
                .untilAsserted(() -> assertThat(ttlRepository.getBlockMfaFailCount("u-ttl"))
                        .as("fail count must return 0 after the TTL expires in both modes")
                        .isZero());
    }
}
