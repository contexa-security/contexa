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

class InMemoryZeroTrustActionRepositoryChallengeHoldContractTest
        extends AbstractZeroTrustActionRepositoryChallengeHoldContractTest {

    private final AdjustableClock clock = new AdjustableClock();

    @Override
    protected ZeroTrustActionRepository createRepository() {
        return new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock);
    }

    @Test
    @DisplayName("it lapses when the CHALLENGE would have, and no later")
    void itLapsesWithTheChallenge() {
        InMemoryZeroTrustActionRepository memory = (InMemoryZeroTrustActionRepository) repository;
        challenge();
        clock.advance(Duration.ofMinutes(20));
        memory.holdChallengeForOtherSessions(user, "context-victim");
        memory.saveActionWithPrevious(user, ZeroTrustAction.ALLOW, "context-victim");

        clock.advance(Duration.ofMinutes(9));
        assertThat(memory.getCurrentAction(user, "context-attacker")).isEqualTo(ZeroTrustAction.CHALLENGE);

        clock.advance(Duration.ofMinutes(2));
        assertThat(memory.getCurrentAction(user, "context-attacker")).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    @DisplayName("a user something is held for is not released by the bound on users")
    void theBoundKeepsIt() {
        InMemoryZeroTrustActionRepository memory = new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock, 1);
        repository = memory;
        challenge();
        memory.holdChallengeForOtherSessions(user, "context-victim");
        memory.saveActionWithPrevious(user, ZeroTrustAction.ALLOW, "context-victim");
        clock.advance(Duration.ofSeconds(20));

        memory.saveAction("another-user", ZeroTrustAction.ALLOW, Map.of());
        memory.removeExpiredEntries();

        assertThat(memory.getCurrentAction(user, "context-attacker")).isEqualTo(ZeroTrustAction.CHALLENGE);
    }
}
