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

import io.contexa.contexacore.util.ErrorLogThrottle;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.common.TopicPartition;
import org.springframework.kafka.listener.ConsumerAwareRebalanceListener;
import org.springframework.kafka.support.Acknowledgment;

import java.time.Clock;
import java.time.Duration;
import java.util.Collection;
import java.util.Map;
import java.util.NavigableMap;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Keeps what is committed of each partition below its first record the analysis is not done with, so that a node that
 * dies leaves that record and those after it to be delivered again: killing the application does not take a decision
 * away. The consumer is never paused: a slow decision holds back a commit, not what comes in. A record decided before
 * and delivered again finds its processing claim, or its decision on record, and costs no model call.
 * <p>
 * The order the records came in is what counts, not their offsets' arithmetic: a topic may have gaps. An acknowledgment
 * says that everything before its record is processed, so only the last of a run of settled records is ever used, and
 * only it is kept: an acknowledgment holds its record in memory, and behind one slow decision a node reads on.
 * <p>
 * A record the analysis does not finish within the limit stops holding the commit when the next event of its partition
 * comes or is settled. Its analysis goes on if it still runs; only its second chance is gone, which is counted and
 * reported. A partition that goes to another consumer is forgotten: the analyses of its records go on, and the commit is
 * left to the new owner, which gets them delivered again.
 */
@Slf4j
public class DecidedRecordAcknowledger implements ConsumerAwareRebalanceListener {

    private static final Duration REPORT_INTERVAL = Duration.ofMinutes(1);

    private final Duration decisionLimit;
    private final Clock clock;
    private final ErrorLogThrottle passedReports;
    private final Map<TopicPartition, HeldPartition> partitions = new ConcurrentHashMap<>();
    private final AtomicLong acknowledgments = new AtomicLong();
    private final AtomicLong passedUndecided = new AtomicLong();

    /** @param decisionLimit how long a record may hold the commit of its partition */
    public DecidedRecordAcknowledger(Duration decisionLimit) {
        this(decisionLimit, Clock.systemUTC());
    }

    DecidedRecordAcknowledger(Duration decisionLimit, Clock clock) {
        this.decisionLimit = decisionLimit;
        this.clock = clock;
        this.passedReports = new ErrorLogThrottle(REPORT_INTERVAL, clock::millis);
    }

    /** Holds a record, before the analysis can be done with it. A record delivered again keeps its place and its time. */
    public void taken(String topic, int partition, long offset, Acknowledgment acknowledgment) {
        partitions.computeIfAbsent(new TopicPartition(topic, partition), ignored -> new HeldPartition(null))
                .taken(topic, partition, offset, acknowledgment);
    }

    /** The analysis is done with the record, on whatever thread; a record not held changes nothing. */
    public void settled(String topic, int partition, long offset) {
        HeldPartition held = partitions.get(new TopicPartition(topic, partition));
        if (held != null) {
            held.settled(topic, partition, offset);
        }
    }

    /** The records held for the analysis, on this node. */
    public long undecidedRecords() {
        return partitions.values().stream().mapToLong(HeldPartition::undecided).sum();
    }

    /** The commits asked for since the start. */
    public long acknowledgments() {
        return acknowledgments.get();
    }

    /** The records the commit went past without their analysis being done, since the start. */
    public long passedUndecided() {
        return passedUndecided.get();
    }

    long heldAcknowledgments() {
        return partitions.values().stream().mapToLong(HeldPartition::acknowledgmentsHeld).sum();
    }

    @Override
    public void onPartitionsAssigned(Consumer<?, ?> consumer, Collection<TopicPartition> assigned) {
        assigned.forEach(partition -> {
            HeldPartition former = partitions.put(partition, new HeldPartition(consumer));
            if (former != null) {
                former.forget();
            }
        });
    }

    /** Before the container's last commit: what was acknowledged is in it, and nothing is acknowledged after it. */
    @Override
    public void onPartitionsRevokedBeforeCommit(Consumer<?, ?> consumer, Collection<TopicPartition> revoked) {
        forget(consumer, revoked);
    }

    @Override
    public void onPartitionsLost(Consumer<?, ?> consumer, Collection<TopicPartition> lost) {
        forget(consumer, lost);
    }

    /** A consumer thrown out of its group may learn it only after the partition went to another consumer of this node. */
    private void forget(Consumer<?, ?> consumer, Collection<TopicPartition> gone) {
        gone.forEach(partition -> partitions.computeIfPresent(partition, (key, held) -> {
            if (!held.heldFor(consumer)) {
                return held;
            }
            held.forget();
            return null;
        }));
    }

    private record Undecided(Acknowledgment acknowledgment, long takenAt) {
    }

    private final class HeldPartition {

        private final Consumer<?, ?> consumer;
        private final NavigableMap<Long, Undecided> undecided = new TreeMap<>();
        /** The last record of each run of settled records past the first undecided one. */
        private final NavigableMap<Long, Acknowledgment> decided = new TreeMap<>();
        private long acknowledgedUpTo = -1L;

        private HeldPartition(Consumer<?, ?> consumer) {
            this.consumer = consumer;
        }

        private boolean heldFor(Consumer<?, ?> asking) {
            return consumer == null || consumer == asking;
        }

        private synchronized void taken(String topic, int partition, long offset, Acknowledgment acknowledgment) {
            if (offset > acknowledgedUpTo && !decided.containsKey(offset)) {
                Undecided known = undecided.get(offset);
                undecided.put(offset, new Undecided(acknowledgment, known != null ? known.takenAt() : clock.millis()));
            }
            moveOn(topic, partition);
        }

        private synchronized void settled(String topic, int partition, long offset) {
            Undecided record = undecided.remove(offset);
            if (record != null) {
                decide(offset, record.acknowledgment());
                moveOn(topic, partition);
            }
        }

        private void decide(long offset, Acknowledgment acknowledgment) {
            Long undecidedBelow = undecided.lowerKey(offset);
            (undecidedBelow != null ? decided.subMap(undecidedBelow, false, offset, false) : decided.headMap(offset, false))
                    .clear();
            Long decidedAbove = decided.higherKey(offset);
            Long undecidedAbove = undecided.higherKey(offset);
            if (decidedAbove == null || (undecidedAbove != null && undecidedAbove < decidedAbove)) {
                decided.put(offset, acknowledgment);
            }
        }

        private void moveOn(String topic, int partition) {
            long takenBefore = clock.millis() - decisionLimit.toMillis();
            while (!undecided.isEmpty() && undecided.firstEntry().getValue().takenAt() < takenBefore) {
                Map.Entry<Long, Undecided> overdue = undecided.pollFirstEntry();
                decide(overdue.getKey(), overdue.getValue().acknowledgment());
                reportPassed(topic, partition, overdue.getKey());
            }
            NavigableMap<Long, Acknowledgment> ready =
                    undecided.isEmpty() ? decided : decided.headMap(undecided.firstKey(), false);
            Map.Entry<Long, Acknowledgment> last = ready.lastEntry();
            if (last != null) {
                ready.clear();
                acknowledgedUpTo = last.getKey();
                acknowledge(last.getValue(), topic, partition, last.getKey());
            }
        }

        /** Under the lock, so that commits leave in order and none leaves after the partition is forgotten. */
        private void acknowledge(Acknowledgment acknowledgment, String topic, int partition, long offset) {
            try {
                acknowledgment.acknowledge();
                acknowledgments.incrementAndGet();
            } catch (RuntimeException failure) {
                log.error("[DecidedRecordAcknowledger] A commit failed and the next one will cover it - topic: {}, "
                        + "partition: {}, offset: {}", topic, partition, offset, failure);
            }
        }

        private void reportPassed(String topic, int partition, long offset) {
            passedUndecided.incrementAndGet();
            long notReported = passedReports.tryAcquire();
            if (notReported != ErrorLogThrottle.SUPPRESSED) {
                log.error("[DecidedRecordAcknowledger] The analysis of a record did not end within {}, so the commit goes "
                        + "past it: a node that dies now does not leave it to be delivered again - topic: {}, partition: {}, "
                        + "offset: {}, others since the last report: {}", decisionLimit, topic, partition, offset, notReported);
            }
        }

        private synchronized void forget() {
            undecided.clear();
            decided.clear();
        }

        private synchronized long undecided() {
            return undecided.size();
        }

        private synchronized long acknowledgmentsHeld() {
            return undecided.size() + decided.size();
        }
    }
}
