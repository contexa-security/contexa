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
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * QF-48 (DD-66): an analysis past its TTL is absent to every read, as its Redis key is, so the sweep removes it at once;
 * its last verified record stays its 24 h, as its Redis key does, and still answers an unresolved ESCALATE.
 */
class InMemoryZeroTrustActionRepositoryExpiredAnalysisTest {

    private final AdjustableClock clock = new AdjustableClock();
    private final InMemoryZeroTrustActionRepository repository =
            new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock);

    @Test
    void theSweepRemovesAnAnalysisPastItsTtlAndKeepsItsLastVerifiedRecord() {
        repository.saveAction("alice", ZeroTrustAction.ALLOW, Map.of("reasoning", "a long model reasoning"));
        repository.saveAction("bob", ZeroTrustAction.CHALLENGE, Map.of("reasoning", "challenged"));

        clock.advance(Duration.ofMinutes(31));
        repository.removeExpiredEntries();

        for (String user : new String[]{"alice", "bob"}) {
            assertThat(repository.holdsAnalysisFor(user)).as(user).isFalse();
            assertThat(repository.holdsLastVerifiedFor(user)).as(user).isTrue();
            assertThat(repository.getCurrentAction(user, "ctx")).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        }
    }

    @Test
    void anUnresolvedEscalateStillReadsAsEscalateOnceItsAnalysisIsRemoved() {
        repository.saveAction("carol", ZeroTrustAction.ESCALATE, Map.of());

        clock.advance(Duration.ofMinutes(6));
        repository.removeExpiredEntries();

        assertThat(repository.holdsAnalysisFor("carol")).isFalse();
        assertThat(repository.getCurrentAction("carol", "ctx")).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(repository.getCurrentAction("carol")).isEqualTo(ZeroTrustAction.ESCALATE);
    }

    @Test
    void aLogoutKeepsAnUnresolvedEscalateWhoseAnalysisIsRemoved() {
        repository.saveAction("erin", ZeroTrustAction.ESCALATE, Map.of());
        clock.advance(Duration.ofMinutes(6));
        repository.removeExpiredEntries();

        repository.removeLogoutData("erin");

        assertThat(repository.getCurrentAction("erin", "ctx")).isEqualTo(ZeroTrustAction.ESCALATE);
        assertThat(repository.getLastVerifiedAction("erin")).isEqualTo(ZeroTrustAction.ESCALATE);
    }

    @Test
    void anAnalysisWithoutTtlStays() {
        repository.saveAction("dave", ZeroTrustAction.BLOCK, Map.of());

        clock.advance(Duration.ofDays(2));
        repository.removeExpiredEntries();

        assertThat(repository.holdsAnalysisFor("dave")).isTrue();
        assertThat(repository.getCurrentAction("dave", "ctx")).isEqualTo(ZeroTrustAction.BLOCK);
    }
}
