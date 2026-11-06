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
package io.contexa.contexacore.autonomous.event.listener;

import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.common.TopicPartition;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.kafka.support.Acknowledgment;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;

/**
 * What is committed stays below the first record the analysis has not finished: a node that dies leaves that record and
 * those after it to be delivered again.
 */
@Timeout(value = 60, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class DecidedRecordAcknowledgerTest {

    private static final String TOPIC = "security.events.authentication";
    private static final Duration LIMIT = Duration.ofMinutes(13);

    private final MovingClock clock = new MovingClock();
    private final DecidedRecordAcknowledger decided = new DecidedRecordAcknowledger(LIMIT, clock);
    /** The commits as the broker would see them: partition and offset of each acknowledged record, in order. */
    private final List<String> commits = new CopyOnWriteArrayList<>();

    private Acknowledgment recordAt(int partition, long offset) {
        return () -> commits.add(partition + ":" + offset);
    }

    private void take(long... offsets) {
        for (long offset : offsets) {
            decided.taken(TOPIC, 0, offset, recordAt(0, offset));
        }
    }

    private void settle(long... offsets) {
        for (long offset : offsets) {
            decided.settled(TOPIC, 0, offset);
        }
    }

    // ----- the commit stays below what is undecided -----

    @Test
    void nothingIsCommittedWhileTheFirstRecordIsUndecided() {
        take(10, 11, 12);

        settle(11, 12);

        assertThat(commits).isEmpty();
    }

    @Test
    void decisionsInAnyOrderCommitOnlyWhatHasNothingUndecidedBelowIt() {
        take(10, 11, 12, 13);

        settle(11);
        settle(10);

        assertThat(commits).containsExactly("0:11");

        settle(13);
        assertThat(commits).containsExactly("0:11");

        settle(12);
        assertThat(commits).containsExactly("0:11", "0:13");
    }

    @Test
    void theOffsetsOfATopicMayHaveGaps() {
        take(10, 13, 20);

        settle(13);
        settle(10);

        assertThat(commits).containsExactly("0:13");
    }

    @Test
    void onePartitionDoesNotHoldBackAnother() {
        decided.taken(TOPIC, 0, 1, recordAt(0, 1));
        decided.taken(TOPIC, 1, 1, recordAt(1, 1));

        decided.settled(TOPIC, 1, 1);

        assertThat(commits).containsExactly("1:1");
    }

    @Test
    void aTopicDoesNotHoldBackAnother() {
        decided.taken(TOPIC, 0, 1, recordAt(0, 1));
        decided.taken("security.events.authorization", 0, 1, () -> commits.add("other:1"));

        decided.settled("security.events.authorization", 0, 1);

        assertThat(commits).containsExactly("other:1");
    }

    // ----- a record delivered twice -----

    @Test
    void aRecordDeliveredAgainWhileUndecidedKeepsItsPlaceAndTakesTheNewAcknowledgment() {
        take(10);
        decided.taken(TOPIC, 0, 10, () -> commits.add("second delivery"));

        settle(10);

        assertThat(commits).containsExactly("second delivery");
    }

    @Test
    void aRecordDeliveredAgainWhileUndecidedDoesNotStartItsTimeAgain() {
        take(10);
        clock.pass(LIMIT.minusMinutes(1));
        take(10);
        clock.pass(Duration.ofMinutes(2));

        take(11);

        assertThat(commits).as("the limit runs from the first delivery").containsExactly("0:10");
    }

    @Test
    void aRecordAlreadyDecidedIsNotOpenedAgain() {
        take(10, 11);
        settle(11);

        take(11);
        settle(10);

        assertThat(commits).containsExactly("0:11");
        assertThat(decided.undecidedRecords()).isZero();
    }

    @Test
    void whatWasCommittedIsNotOpenedAgainNorCommittedBack() {
        take(10, 11);
        settle(10, 11);

        take(10);
        settle(10);

        assertThat(commits).containsExactly("0:10", "0:11");
        assertThat(decided.undecidedRecords()).isZero();
    }

    @Test
    void aDecisionOnARecordNotHeldChangesNothing() {
        take(10);

        settle(99);

        assertThat(commits).isEmpty();
        assertThat(decided.undecidedRecords()).isEqualTo(1);
    }

    @Test
    void aSecondDecisionOnARecordChangesNothing() {
        take(10, 11);
        settle(11, 11);

        assertThat(decided.undecidedRecords()).isEqualTo(1);
        assertThat(commits).isEmpty();
    }

    // ----- a rebalance -----

    @Test
    void aPartitionTakenAwayCommitsNothingMore() {
        Consumer<?, ?> consumer = mock(Consumer.class);
        TopicPartition partition = new TopicPartition(TOPIC, 0);
        decided.onPartitionsAssigned(consumer, List.of(partition));
        take(10, 11);

        decided.onPartitionsRevokedBeforeCommit(consumer, List.of(partition));
        settle(10, 11);

        assertThat(commits).as("the next owner commits it").isEmpty();
        assertThat(decided.undecidedRecords()).isZero();
    }

    @Test
    void aPartitionLostCommitsNothingMore() {
        Consumer<?, ?> consumer = mock(Consumer.class);
        TopicPartition partition = new TopicPartition(TOPIC, 0);
        decided.onPartitionsAssigned(consumer, List.of(partition));
        take(10);

        decided.onPartitionsLost(consumer, List.of(partition));
        settle(10);

        assertThat(commits).isEmpty();
    }

    @Test
    void onlyThePartitionsTakenAwayAreForgotten() {
        Consumer<?, ?> consumer = mock(Consumer.class);
        TopicPartition taken = new TopicPartition(TOPIC, 0);
        TopicPartition kept = new TopicPartition(TOPIC, 1);
        decided.onPartitionsAssigned(consumer, List.of(taken, kept));
        decided.taken(TOPIC, 0, 1, recordAt(0, 1));
        decided.taken(TOPIC, 1, 1, recordAt(1, 1));

        decided.onPartitionsRevokedBeforeCommit(consumer, List.of(taken));
        decided.settled(TOPIC, 1, 1);

        assertThat(commits).containsExactly("1:1");
    }

    @Test
    void aPartitionThatComesBackStartsFromWhatIsDeliveredAgain() {
        Consumer<?, ?> consumer = mock(Consumer.class);
        TopicPartition partition = new TopicPartition(TOPIC, 0);
        decided.onPartitionsAssigned(consumer, List.of(partition));
        take(10, 11);
        settle(10);
        decided.onPartitionsRevokedBeforeCommit(consumer, List.of(partition));
        decided.onPartitionsAssigned(consumer, List.of(partition));

        take(11, 12);
        settle(11);
        settle(12);

        assertThat(commits).containsExactly("0:10", "0:11", "0:12");
    }

    @Test
    void aPartitionAssignedAnewDoesNotInheritWhatWasHeld() {
        Consumer<?, ?> consumer = mock(Consumer.class);
        TopicPartition partition = new TopicPartition(TOPIC, 0);
        decided.onPartitionsAssigned(consumer, List.of(partition));
        take(10);

        decided.onPartitionsAssigned(consumer, List.of(partition));

        assertThat(decided.undecidedRecords()).isZero();
    }

    /** Two consumers of the node: the one thrown out learns only later that the partition is gone, by then the other's. */
    @Test
    void aConsumerThatLostAPartitionDoesNotForgetWhatItsNewOwnerHolds() {
        Consumer<?, ?> oldOwner = mock(Consumer.class);
        Consumer<?, ?> newOwner = mock(Consumer.class);
        TopicPartition partition = new TopicPartition(TOPIC, 0);
        decided.onPartitionsAssigned(oldOwner, List.of(partition));
        decided.onPartitionsAssigned(newOwner, List.of(partition));
        take(10, 11);

        decided.onPartitionsLost(oldOwner, List.of(partition));

        assertThat(decided.undecidedRecords()).isEqualTo(2);
        settle(11);
        assertThat(commits).as("10 is still undecided").isEmpty();
    }

    // ----- a record that never ends -----

    @Test
    void aRecordPastTheLimitNoLongerHoldsTheCommitOnceTheNextRecordComes() {
        take(10);
        clock.pass(LIMIT.plusSeconds(1));

        take(11);
        settle(11);

        assertThat(commits).containsExactly("0:10", "0:11");
        assertThat(decided.passedUndecided()).isEqualTo(1);
    }

    @Test
    void aRecordPastTheLimitNoLongerHoldsTheRecordsDecidedAfterIt() {
        take(10, 11);
        settle(11);
        clock.pass(LIMIT.plusSeconds(1));

        take(12);

        assertThat(commits).containsExactly("0:11");
    }

    @Test
    void anotherDecisionAlsoLetsTheCommitPassARecordPastTheLimit() {
        take(10, 11, 12);
        clock.pass(LIMIT.plusSeconds(1));

        settle(12);

        assertThat(commits).as("11 is past the limit too").containsExactly("0:12");
    }

    @Test
    void aRecordWithinTheLimitHoldsTheCommit() {
        take(10);
        clock.pass(LIMIT.minusSeconds(1));

        take(11);
        settle(11);

        assertThat(commits).isEmpty();
        assertThat(decided.passedUndecided()).isZero();
    }

    @Test
    void theDecisionOfARecordPassedChangesNothing() {
        take(10);
        clock.pass(LIMIT.plusSeconds(1));
        take(11);
        settle(11);

        settle(10);

        assertThat(commits).containsExactly("0:10", "0:11");
        assertThat(decided.passedUndecided()).isEqualTo(1);
    }

    @Test
    void aRecordPassedIsNoLongerCountedUndecided() {
        take(10);
        clock.pass(LIMIT.plusSeconds(1));

        take(11);

        assertThat(decided.undecidedRecords()).isEqualTo(1);
    }

    // ----- what it costs the node -----

    @Test
    void aFailedCommitReachesNeitherTheAnalysisNorTheNextCommit() {
        decided.taken(TOPIC, 0, 10, () -> {
            throw new IllegalStateException("The consumer is gone");
        });
        take(11);

        assertThatCode(() -> settle(10)).doesNotThrowAnyException();
        settle(11);

        assertThat(commits).containsExactly("0:11");
    }

    /** An acknowledgment holds its record: behind one slow decision the node would keep every record it read since. */
    @Test
    void behindOneUndecidedRecordOnlyTheLastOfTheDecidedRunIsKept() {
        take(0);
        for (long offset = 1; offset <= 10_000; offset++) {
            take(offset);
            settle(offset);
        }

        assertThat(decided.heldAcknowledgments()).isEqualTo(2);

        settle(0);

        assertThat(commits).containsExactly("0:10000");
        assertThat(decided.heldAcknowledgments()).isZero();
    }

    @Test
    void betweenUndecidedRecordsEachDecidedRunKeepsOne() {
        take(0, 1, 2, 3, 4, 5, 6);

        settle(1, 2, 4, 5);

        assertThat(decided.heldAcknowledgments()).as("0, 3, 6 undecided, 2 and 5 end their runs").isEqualTo(5);
        settle(3);
        assertThat(decided.heldAcknowledgments()).as("0, 6 undecided, 5 ends the run").isEqualTo(3);
        settle(0);
        assertThat(commits).containsExactly("0:5");
    }

    @Test
    void itCountsWhatItHoldsAndWhatItCommitted() {
        take(10, 11, 12);
        settle(10, 11);

        assertThat(decided.undecidedRecords()).isEqualTo(1);
        assertThat(decided.acknowledgments()).isEqualTo(2);
    }

    @Test
    void decisionsFromManyThreadsEndWithEverythingCommittedInOrder() throws Exception {
        int records = 20_000;
        Map<Long, Boolean> acknowledged = new ConcurrentHashMap<>();
        List<Long> order = Collections.synchronizedList(new ArrayList<>());
        List<Long> offsets = new ArrayList<>();
        for (long offset = 0; offset < records; offset++) {
            long at = offset;
            decided.taken(TOPIC, 0, at, () -> {
                acknowledged.put(at, Boolean.TRUE);
                order.add(at);
            });
            offsets.add(at);
        }
        Collections.shuffle(offsets, new Random(35));
        int threads = 8;
        ExecutorService analysis = Executors.newFixedThreadPool(threads);
        CountDownLatch done = new CountDownLatch(threads);
        for (int thread = 0; thread < threads; thread++) {
            List<Long> share = offsets.subList(thread * records / threads, (thread + 1) * records / threads);
            analysis.execute(() -> {
                share.forEach(offset -> decided.settled(TOPIC, 0, offset));
                done.countDown();
            });
        }

        assertThat(done.await(30, TimeUnit.SECONDS)).isTrue();
        analysis.shutdown();

        assertThat(order).isSorted().contains(records - 1L);
        assertThat(decided.undecidedRecords()).isZero();
        assertThat(decided.heldAcknowledgments()).isZero();
    }

    private static final class MovingClock extends Clock {
        private Instant now = Instant.parse("2026-11-06T00:00:00Z");

        void pass(Duration elapsed) {
            now = now.plus(elapsed);
        }

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
            return now;
        }
    }
}
