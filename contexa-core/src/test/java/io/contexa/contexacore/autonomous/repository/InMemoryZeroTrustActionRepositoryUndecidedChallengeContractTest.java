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

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.testsupport.AdjustableClock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryZeroTrustActionRepositoryUndecidedChallengeContractTest
        extends AbstractZeroTrustActionRepositoryUndecidedChallengeContractTest {

    private final AdjustableClock clock = new AdjustableClock();

    @Override
    protected ZeroTrustActionRepository createRepository() {
        return new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock);
    }

    @Test
    @DisplayName("it lasts a CHALLENGE's time, not the minute of a CHALLENGE no model decided")
    void itLastsAChallengesTime() {
        repository.writeUndecidedChallenge(user, Map.of("contextBindingHash", "context-next-session"));

        clock.advance(Duration.ofMinutes(29));
        assertThat(repository.getCurrentAction(user, "context-next-session")).isEqualTo(ZeroTrustAction.CHALLENGE);

        clock.advance(Duration.ofMinutes(2));
        assertThat(repository.getCurrentAction(user, "context-next-session")).isNotEqualTo(ZeroTrustAction.CHALLENGE);
    }
}
