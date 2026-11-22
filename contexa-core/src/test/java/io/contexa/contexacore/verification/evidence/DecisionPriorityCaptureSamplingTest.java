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
package io.contexa.contexacore.verification.evidence;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Plan 3.6: which decisions are sealed. The window after a change and the share of the requests seal as before; beside
 * them a decision that stopped the request is sealed, and an allowed one with a sign of risk, while the day's packages
 * are under the daily limit the store counts.
 */
class DecisionPriorityCaptureSamplingTest {

    private static final int UNKNOWN_FACTS = 3;

    private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-11-22T10:00:00Z"));
    private final Clock clock = new Clock() {
        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now.get();
        }
    };
    /** The packages of the day the store holds, and the times it was asked from. */
    private final AtomicLong stored = new AtomicLong();
    private final List<Instant> asked = new ArrayList<>();
    /** What the window and the share answer. */
    private boolean windowOrShare;

    // ----- rule 2: the action the decision ended in -----

    @Test
    void aDecisionThatStoppedTheRequestIsSealed() {
        DecisionPriorityCaptureSampling sampling = sampling(100);

        assertThat(sampling.shouldSeal(sealed("challenge"), decision("CHALLENGE"))).isTrue();
        assertThat(sampling.shouldSeal(sealed("escalate"), decision("ESCALATE"))).isTrue();
        assertThat(sampling.shouldSeal(sealed("block"), decision("BLOCK"))).isTrue();
    }

    @Test
    void anAllowedDecisionWithoutASignOfRiskIsLeftToTheWindowAndTheShare() {
        DecisionPriorityCaptureSampling sampling = sampling(100);

        assertThat(sampling.shouldSeal(sealed("allow-1"), decision("ALLOW"))).isFalse();
        windowOrShare = true;
        assertThat(sampling.shouldSeal(sealed("allow-2"), decision("ALLOW"))).isTrue();
    }

    /** A decision that neither stopped nor allowed the request (no action, an analysis still pending) has no priority. */
    @Test
    void anActionThatIsNeitherAStopNorAnAllowIsLeftToTheWindowAndTheShare() {
        DecisionPriorityCaptureSampling sampling = sampling(100);

        assertThat(sampling.shouldSeal(sealed("pending"), risky("PENDING_ANALYSIS"))).isFalse();
        assertThat(sampling.shouldSeal(sealed("no-action"), risky(null))).isFalse();
    }

    /** The package alone, or a decision the capture could not read, is sealed as before. */
    @Test
    void withoutTheDecisionTheWindowAndTheShareDecide() {
        DecisionPriorityCaptureSampling sampling = sampling(100);

        assertThat(sampling.shouldSeal(sealed("alone-1"))).isFalse();
        assertThat(sampling.shouldSeal(sealed("alone-2"), null)).isFalse();
        windowOrShare = true;
        assertThat(sampling.shouldSeal(sealed("alone-3"))).isTrue();
        assertThat(sampling.shouldSeal(sealed("alone-4"), null)).isTrue();
    }

    // ----- rule 3: the signs of risk of an allowed decision -----

    @Test
    void anAllowedDecisionIsSealedForEachSignOfRisk() {
        DecisionPriorityCaptureSampling sampling = sampling(100);

        assertThat(sampling.shouldSeal(sealed("hypothesis"),
                new SealedCaptureDecision("ALLOW", "H3", false, false, 0, "ESTABLISHED")))
                .as("the most likely explanation is not legitimate work").isTrue();
        assertThat(sampling.shouldSeal(sealed("second"),
                new SealedCaptureDecision("ALLOW", "H1", true, false, 0, "ESTABLISHED")))
                .as("the second analysis decided").isTrue();
        assertThat(sampling.shouldSeal(sealed("again"),
                new SealedCaptureDecision("ALLOW", "H1", false, true, 0, "ESTABLISHED")))
                .as("the model was asked again").isTrue();
        assertThat(sampling.shouldSeal(sealed("unknown"),
                new SealedCaptureDecision("ALLOW", "H1", false, false, UNKNOWN_FACTS, "ESTABLISHED")))
                .as("as many unknown facts as the threshold").isTrue();
        assertThat(sampling.shouldSeal(sealed("provisional"),
                new SealedCaptureDecision("ALLOW", "H1", false, false, 0, "PROVISIONAL")))
                .as("a provisional baseline").isTrue();
        assertThat(sampling.shouldSeal(sealed("none"),
                new SealedCaptureDecision("ALLOW", "H1", false, false, 0, "NONE")))
                .as("no baseline").isTrue();
    }

    @Test
    void anAllowedDecisionJustUnderEachSignIsNotSealed() {
        DecisionPriorityCaptureSampling sampling = sampling(100);

        assertThat(sampling.shouldSeal(sealed("legitimate"),
                new SealedCaptureDecision("ALLOW", "H1", false, false, UNKNOWN_FACTS - 1, "ESTABLISHED")))
                .as("legitimate work, one unknown fact under the threshold, an established baseline").isFalse();
        assertThat(sampling.shouldSeal(sealed("lower-case"),
                new SealedCaptureDecision("ALLOW", "h1", false, false, 0, "ESTABLISHED"))).isFalse();
        assertThat(sampling.shouldSeal(sealed("nothing-kept"),
                new SealedCaptureDecision("ALLOW", null, false, false, null, null)))
                .as("a value the decision did not keep is no sign").isFalse();
    }

    // ----- rule 4: the daily limit -----

    @Test
    void pastTheDailyLimitOnlyTheWindowAndTheShareSeal() {
        DecisionPriorityCaptureSampling sampling = sampling(3);

        assertThat(IntStream.range(0, 3).mapToObj(index -> sampling.shouldSeal(sealed("stop-" + index),
                decision("BLOCK")))).containsOnly(true);
        assertThat(sampling.shouldSeal(sealed("stop-over"), decision("BLOCK"))).isFalse();
        assertThat(sampling.shouldSeal(sealed("risk-over"), risky("ALLOW"))).isFalse();
        assertThat(sampling.notSealedOverLimit()).as("what the limit held back is counted").isEqualTo(2);

        // The window and the share are never held back, so the day falls back to them.
        windowOrShare = true;
        assertThat(sampling.shouldSeal(sealed("window-over"), decision("ALLOW"))).isTrue();
        assertThat(sampling.shouldSeal(sealed("stop-in-window"), decision("BLOCK"))).isTrue();
        assertThat(sampling.notSealedOverLimit()).isEqualTo(2);
    }

    @Test
    void whatTheWindowAndTheShareSealCountsTowardTheLimit() {
        DecisionPriorityCaptureSampling sampling = sampling(3);
        windowOrShare = true;
        sampling.shouldSeal(sealed("window-1"), decision("ALLOW"));
        sampling.shouldSeal(sealed("window-2"), decision("ALLOW"));
        windowOrShare = false;

        assertThat(sampling.shouldSeal(sealed("stop-third"), decision("CHALLENGE"))).isTrue();
        assertThat(sampling.shouldSeal(sealed("stop-fourth"), decision("CHALLENGE"))).isFalse();
    }

    /** The day's count is the store's, so the servers that share it stay near one limit without a read per decision. */
    @Test
    void theDaysCountIsReadFromTheStoreAndKeptForTheRefreshTime() {
        DecisionPriorityCaptureSampling sampling = sampling(10);
        stored.set(8);

        assertThat(sampling.shouldSeal(sealed("stop-9"), decision("BLOCK"))).isTrue();
        assertThat(sampling.shouldSeal(sealed("stop-10"), decision("BLOCK"))).isTrue();
        assertThat(sampling.shouldSeal(sealed("stop-11"), decision("BLOCK"))).isFalse();
        assertThat(asked).as("one read of the store, from the start of the UTC day")
                .containsExactly(Instant.parse("2026-11-22T00:00:00Z"));

        // Packages of the day were removed meanwhile; the count is read again once the refresh time passed.
        stored.set(4);
        now.set(now.get().plus(DecisionPriorityCaptureSampling.REFRESH).minusMillis(1));
        assertThat(sampling.shouldSeal(sealed("stop-still-over"), decision("BLOCK"))).isFalse();
        assertThat(asked).hasSize(1);
        now.set(now.get().plusMillis(1));
        assertThat(sampling.shouldSeal(sealed("stop-under-again"), decision("BLOCK"))).isTrue();
        assertThat(asked).hasSize(2);
    }

    @Test
    void whatAnotherServerSealedIsSeenAtTheNextRead() {
        DecisionPriorityCaptureSampling sampling = sampling(10);
        assertThat(sampling.shouldSeal(sealed("stop-first"), decision("BLOCK"))).isTrue();

        stored.set(10);
        now.set(now.get().plus(DecisionPriorityCaptureSampling.REFRESH));

        assertThat(sampling.shouldSeal(sealed("stop-after"), decision("BLOCK"))).isFalse();
    }

    @Test
    void aNewUtcDayStartsTheCountAgain() {
        DecisionPriorityCaptureSampling sampling = sampling(1);
        assertThat(sampling.shouldSeal(sealed("today-1"), decision("BLOCK"))).isTrue();
        assertThat(sampling.shouldSeal(sealed("today-2"), decision("BLOCK"))).isFalse();

        now.set(Instant.parse("2026-11-23T00:00:01Z"));

        assertThat(sampling.shouldSeal(sealed("tomorrow-1"), decision("BLOCK"))).isTrue();
        assertThat(asked).containsExactly(Instant.parse("2026-11-22T00:00:00Z"), Instant.parse("2026-11-23T00:00:00Z"));
    }

    /** A store that cannot be counted holds no capture back: the limit goes on from this server's own count. */
    @Test
    void aStoreThatCannotBeCountedLeavesTheLimitOnThisServersCount() {
        DecisionPriorityCaptureSampling sampling = new DecisionPriorityCaptureSampling(evidencePackage -> false, 2,
                UNKNOWN_FACTS, since -> {
                    throw new IllegalStateException("the store is down");
                }, clock);

        assertThat(sampling.shouldSeal(sealed("stop-1"), decision("BLOCK"))).isTrue();
        assertThat(sampling.shouldSeal(sealed("stop-2"), decision("BLOCK"))).isTrue();
        assertThat(sampling.shouldSeal(sealed("stop-3"), decision("BLOCK"))).isFalse();
    }

    @Test
    void aLimitOfZeroSealsByTheWindowAndTheShareAlone() {
        DecisionPriorityCaptureSampling sampling = sampling(0);

        assertThat(sampling.shouldSeal(sealed("stop"), decision("BLOCK"))).isFalse();
        assertThat(sampling.shouldSeal(sealed("risk"), risky("ALLOW"))).isFalse();
        windowOrShare = true;
        assertThat(sampling.shouldSeal(sealed("window"), decision("ALLOW"))).isTrue();
        assertThat(asked).as("no count is needed").isEmpty();
        assertThat(sampling.notSealedOverLimit()).isZero();
    }

    // ----- rule 1: the window after a change, as before -----

    @Test
    void theWindowAfterAChangeIsSealedInFullWhateverTheLimit() {
        DecisionPriorityCaptureSampling sampling = new DecisionPriorityCaptureSampling(
                new VersionChangeCaptureSampling(1, 5, new ObjectMapper()), 2, UNKNOWN_FACTS, since -> stored.get(),
                clock);

        // Five allowed decisions without a sign of risk: the window seals all of them, past the limit of two.
        assertThat(IntStream.range(0, 5).mapToObj(index -> sampling.shouldSeal(version("start-" + index),
                decision("ALLOW")))).containsOnly(true);
        // After the window an allowed decision goes by the share, and a stop is held back by the limit the window used.
        String outside = IntStream.range(0, 400).mapToObj(index -> "request-" + index)
                .filter(id -> !sampling.shouldSeal(version(id), decision("ALLOW"))).findFirst().orElseThrow();
        assertThat(sampling.shouldSeal(version(outside), decision("BLOCK"))).isFalse();
        assertThat(sampling.notSealedOverLimit()).isEqualTo(1);
    }

    @Test
    void theLimitAndTheThresholdMustBeInRange() {
        assertThatThrownBy(() -> sampling(-1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DecisionPriorityCaptureSampling(evidencePackage -> false, 10, 0,
                since -> 0L, clock)).isInstanceOf(IllegalArgumentException.class);
    }

    private DecisionPriorityCaptureSampling sampling(int dailyLimit) {
        return new DecisionPriorityCaptureSampling(evidencePackage -> windowOrShare, dailyLimit, UNKNOWN_FACTS,
                since -> {
                    asked.add(since);
                    return stored.get();
                }, clock);
    }

    /** A decision with that action and no sign of risk. */
    private static SealedCaptureDecision decision(String action) {
        return new SealedCaptureDecision(action, "H1", false, false, 0, "ESTABLISHED");
    }

    /** A decision with that action and every sign of risk. */
    private static SealedCaptureDecision risky(String action) {
        return new SealedCaptureDecision(action, "H2", true, true, 9, "NONE");
    }

    private static SealedEvidencePackage sealed(String correlationId) {
        return SealedEvidencePackage.builder().packageId("package-" + correlationId).correlationId(correlationId)
                .build();
    }

    private static SealedEvidencePackage version(String correlationId) {
        return SealedEvidencePackage.builder().packageId("package-" + correlationId).correlationId(correlationId)
                .promptExecutionMetadataJson("{\"promptVersionName\":\"v1.0\",\"promptContentHash\":\"aaa\"}")
                .build();
    }
}
