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

class InMemoryZeroTrustActionRepositoryDecidedContextContractTest
        extends AbstractZeroTrustActionRepositoryDecidedContextContractTest {

    private final AdjustableClock clock = new AdjustableClock();

    @Override
    protected ZeroTrustActionRepository createRepository() {
        return new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock);
    }

    @Override
    protected void theAnalysisLapses() {
        clock.advance(Duration.ofHours(1));
    }

    @Override
    protected void theLastVerifiedRecordsLapse() {
        clock.advance(Duration.ofHours(24));
    }

    private static Map<String, Object> decidedFor(String context) {
        return Map.of("observationId", "observation-1", "processingGeneration", "1", "contextBindingHash", context);
    }

    @Test
    @DisplayName("the sweep releases a record past its time, and the user with it")
    void theSweepReleasesTheRecord() {
        InMemoryZeroTrustActionRepository memory = (InMemoryZeroTrustActionRepository) repository;
        memory.saveFinalAction(user, ZeroTrustAction.ALLOW, decidedFor("context-home"));

        clock.advance(Duration.ofHours(25));
        memory.removeExpiredEntries();

        assertThat(memory.holdsStateFor(user)).isFalse();
    }

    @Test
    @DisplayName("the bound on users releases the record with the user")
    void theBoundReleasesTheRecord() {
        InMemoryZeroTrustActionRepository memory = new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock, 1);
        memory.saveFinalAction(user, ZeroTrustAction.ALLOW, decidedFor("context-home"));
        clock.advance(Duration.ofHours(1));

        memory.saveFinalAction("another-user", ZeroTrustAction.ALLOW, decidedFor("context-other"));
        memory.removeExpiredEntries();

        assertThat(memory.decidedContext(user)).isNull();
        assertThat(memory.holdsStateFor(user)).isFalse();
    }
}
