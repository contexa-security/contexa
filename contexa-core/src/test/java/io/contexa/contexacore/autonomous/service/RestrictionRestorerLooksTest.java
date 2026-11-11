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
package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.store.ContexaStores;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.dao.DataAccessResourceFailureException;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Where the decision store lives outside the server, the blocks the record holds in force are looked at again while the
 * application runs, because a Redis that is emptied loses them all at once. A look writes what is absent and nothing
 * else, takes back a block an administrator released while it was being written, and costs nothing where it can do
 * nothing: in the memory of the server, when decisions are not enforced, and while a store is down.
 */
@ExtendWith(OutputCaptureExtension.class)
class RestrictionRestorerLooksTest {

    private static final Duration LOOK = Duration.ofMillis(60);
    private static final Duration LONG_ENOUGH_FOR_MANY_LOOKS = Duration.ofMillis(700);

    private final Set<String> flags = ConcurrentHashMap.newKeySet();
    private final List<String> writes = new CopyOnWriteArrayList<>();
    private final AtomicInteger reads = new AtomicInteger();
    private final AtomicReference<List<String>> inForce = new AtomicReference<>(List.of());
    private final ZeroTrustActionRepository actions = mock(ZeroTrustActionRepository.class);
    private final IBlockedUserRecorder recorder = mock(IBlockedUserRecorder.class);
    private RestrictionRestorer restorer;

    private void wire() {
        when(actions.restoreBlockedFlag(anyString())).thenAnswer(call -> {
            String user = call.getArgument(0);
            boolean written = flags.add(user);
            if (written) {
                writes.add(user);
            }
            return written;
        });
        doAnswer(call -> flags.remove((String) call.getArgument(0))).when(actions).removeBlockedFlag(anyString());
        when(recorder.blocksInForce()).thenAnswer(call -> {
            reads.incrementAndGet();
            return inForce.get();
        });
    }

    private RestrictionRestorer restorer(ZeroTrustActionRepository repository) {
        restorer = new RestrictionRestorer(() -> repository, () -> recorder, () -> mock(SecurityContextDataStore.class),
                Duration.ofSeconds(5), List.of(Duration.ofMillis(40)), LOOK);
        return restorer;
    }

    @AfterEach
    void stop() {
        if (restorer != null) {
            restorer.stop();
        }
    }

    @Test
    @DisplayName("a block the store lost while the application runs is written again by the next look, and a flag the store has is not touched")
    void aLostBlockIsWrittenAgain() {
        wire();
        inForce.set(List.of("alice", "bob"));
        restorer(actions).start();
        assertThat(flags).containsExactlyInAnyOrder("alice", "bob");
        writes.clear();

        flags.remove("alice");

        Awaitility.await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThat(flags).contains("alice", "bob"));
        assertThat(writes).as("only the flag that was gone was written").containsExactly("alice");
    }

    @Test
    @DisplayName("a user the record does not hold in force is never written, however often it looks")
    void aUserWithoutABlockIsNeverWritten() throws InterruptedException {
        wire();
        inForce.set(List.of("alice"));
        restorer(actions).start();

        Thread.sleep(LONG_ENOUGH_FOR_MANY_LOOKS.toMillis());

        assertThat(flags).containsExactly("alice");
        assertThat(reads.get()).as("it looked again and again").isGreaterThan(3);
    }

    @Test
    @DisplayName("a block an administrator released is not written back by a later look: the record no longer holds it")
    void aReleasedBlockStaysReleased() throws InterruptedException {
        wire();
        inForce.set(List.of("alice"));
        restorer(actions).start();
        assertThat(flags).containsExactly("alice");

        // The release resolves the record first and clears the flag once that is committed.
        inForce.set(List.of());
        flags.remove("alice");
        Thread.sleep(LONG_ENOUGH_FOR_MANY_LOOKS.toMillis());

        assertThat(flags).isEmpty();
        assertThat(writes).containsExactly("alice");
    }

    @Test
    @DisplayName("a block released between the read of the record and the write is taken out again: the write cannot put it back for good")
    void aBlockReleasedWhileItWasBeingWrittenIsTakenOut() {
        wire();
        AtomicBoolean released = new AtomicBoolean();
        when(recorder.blocksInForce()).thenAnswer(call -> {
            reads.incrementAndGet();
            // The first read sees the block; the release is committed and the flag cleared (it was gone) before the write.
            return released.get() ? List.of() : List.of("alice");
        });
        doAnswer(call -> {
            released.set(true);
            writes.add("alice");
            return flags.add("alice");
        }).when(actions).restoreBlockedFlag("alice");

        restorer(actions).start();

        assertThat(writes).containsExactly("alice");
        assertThat(flags).as("the record no longer held the block when it was asked again").isEmpty();
    }

    @Test
    @DisplayName("a block still in force after the write stays: the question after the write answers yes")
    void aBlockThatStaysInForceStays() {
        wire();
        inForce.set(List.of("alice"));

        restorer(actions).start();

        assertThat(flags).containsExactly("alice");
        assertThat(reads.get()).as("the record was read for the write and asked again for the written block").isGreaterThanOrEqualTo(2);
    }

    @Test
    @DisplayName("the memory of the server loses nothing while it runs: no look is made, and the start is the only write")
    void theMemoryOfTheServerIsNotLookedAt() throws InterruptedException {
        wire();
        InMemoryZeroTrustActionRepository memory = new InMemoryZeroTrustActionRepository(0);
        inForce.set(List.of("alice"));
        restorer(memory).start();
        int afterTheStart = reads.get();

        Thread.sleep(LONG_ENOUGH_FOR_MANY_LOOKS.toMillis());

        assertThat(afterTheStart).as("the start read the record").isPositive();
        assertThat(reads.get()).as("the record is not read again").isEqualTo(afterTheStart);
    }

    @Test
    @DisplayName("decisions that are not enforced stop nothing, so nothing is looked at; the look resumes when they are enforced")
    void nothingIsLookedAtWhereDecisionsAreNotEnforced() throws InterruptedException {
        wire();
        AtomicBoolean enforcing = new AtomicBoolean(false);
        inForce.set(List.of("alice"));
        restorer(actions).setEnforcing(enforcing::get);
        restorer.start();
        int afterTheStart = reads.get();
        flags.remove("alice");

        Thread.sleep(LONG_ENOUGH_FOR_MANY_LOOKS.toMillis());
        assertThat(reads.get()).isEqualTo(afterTheStart);
        assertThat(flags).isEmpty();

        enforcing.set(true);
        Awaitility.await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThat(flags).containsExactly("alice"));
    }

    @Test
    @DisplayName("a database that does not answer is reported once, not at every look, the application is not stopped, and the next look that succeeds writes")
    void aDatabaseThatIsDownIsReportedOnce(CapturedOutput output) throws InterruptedException {
        wire();
        AtomicBoolean down = new AtomicBoolean();
        when(recorder.blocksInForce()).thenAnswer(call -> {
            reads.incrementAndGet();
            if (down.get()) {
                throw new IllegalStateException("database is down");
            }
            return List.of("alice");
        });
        restorer(actions).start();
        flags.remove("alice");
        down.set(true);
        int before = reads.get();

        Thread.sleep(LONG_ENOUGH_FOR_MANY_LOOKS.toMillis());

        assertThat(reads.get() - before).as("it kept looking").isGreaterThan(3);
        assertThat(count(output.getAll(), "could not be looked at again")).as("the report").isEqualTo(1);
        assertThat(flags).isEmpty();

        down.set(false);
        Awaitility.await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThat(flags).containsExactly("alice"));
    }

    @Test
    @DisplayName("while a store is known to be down no look is made, and when Redis answers again one is made at once, not at the next look")
    void aLookIsMadeAtOnceWhenRedisAnswersAgain() {
        wire();
        ContexaStores stores = new ContexaStores();
        AtomicBoolean redisUp = new AtomicBoolean(true);
        stores.redis().watchWith(() -> {
            if (!redisUp.get()) {
                throw new IllegalStateException("redis is down");
            }
        });
        inForce.set(List.of("alice"));
        // A wait between looks far longer than the test: only the answer of Redis can write the flag in time.
        restorer = new RestrictionRestorer(() -> actions, () -> recorder, () -> mock(SecurityContextDataStore.class),
                Duration.ofSeconds(5), List.of(Duration.ofMillis(40)), Duration.ofMinutes(10));
        restorer.setContexaStores(stores);
        restorer.start();
        assertThat(flags).containsExactly("alice");

        redisUp.set(false);
        stores.redis().fail(new DataAccessResourceFailureException("redis is down"));
        assertThat(stores.redis().isDown()).isTrue();
        flags.clear();
        redisUp.set(true);

        Awaitility.await().atMost(Duration.ofSeconds(10)).untilAsserted(() -> assertThat(flags).containsExactly("alice"));
        assertThat(stores.redis().isDown()).isFalse();
    }

    @Test
    @DisplayName("no look is made while a store is known to be down, and the looks go on when it answers again")
    void noLookIsMadeWhileAStoreIsDown() throws InterruptedException {
        wire();
        ContexaStores stores = new ContexaStores();
        AtomicBoolean redisUp = new AtomicBoolean(false);
        stores.redis().watchWith(() -> {
            if (!redisUp.get()) {
                throw new IllegalStateException("redis is down");
            }
        });
        inForce.set(List.of("alice"));
        restorer = new RestrictionRestorer(() -> actions, () -> recorder, () -> mock(SecurityContextDataStore.class),
                Duration.ofSeconds(5), List.of(Duration.ofMillis(40)), LOOK);
        restorer.setContexaStores(stores);
        restorer.start();
        stores.redis().fail(new DataAccessResourceFailureException("redis is down"));
        Thread.sleep(200);
        int whileDown = reads.get();

        Thread.sleep(LONG_ENOUGH_FOR_MANY_LOOKS.toMillis());

        assertThat(stores.redis().isDown()).isTrue();
        assertThat(reads.get()).as("the record is not read while Redis is down").isEqualTo(whileDown);

        redisUp.set(true);
        Awaitility.await().atMost(Duration.ofSeconds(10)).untilAsserted(() -> assertThat(reads.get()).isGreaterThan(whileDown));
    }

    @Test
    @DisplayName("a look that took long stretches the wait to twenty times as long: the restorer never uses more than a twentieth of its time")
    void aSlowLookStretchesTheWait() throws InterruptedException {
        wire();
        when(recorder.blocksInForce()).thenAnswer(call -> {
            reads.incrementAndGet();
            Thread.sleep(100);
            return List.of("alice");
        });
        restorer(actions).start();
        int afterTheStart = reads.get();

        Thread.sleep(1200);

        // Each look takes 100 ms, so the wait is 2000 ms and not the 60 ms of a look that is quick: no second look yet.
        assertThat(reads.get() - afterTheStart).isLessThanOrEqualTo(2);
    }

    @Test
    @DisplayName("a look that waited for a database that did not answer does not stretch the wait: the next look comes at the usual time")
    void aLookThatFailedAfterALongWaitIsFollowedAtTheUsualTime() throws InterruptedException {
        wire();
        AtomicBoolean down = new AtomicBoolean();
        when(recorder.blocksInForce()).thenAnswer(call -> {
            reads.incrementAndGet();
            if (down.get()) {
                Thread.sleep(100);
                throw new IllegalStateException("database is down");
            }
            return List.of("alice");
        });
        restorer(actions).start();
        down.set(true);
        int before = reads.get();

        Thread.sleep(1200);

        // Each failed look took 100 ms; a look that did work would have been followed after 2000 ms.
        assertThat(reads.get() - before).isGreaterThanOrEqualTo(4);
    }

    @Test
    @DisplayName("stopping ends the looks")
    void stoppingEndsTheLooks() throws InterruptedException {
        wire();
        inForce.set(List.of("alice"));
        restorer(actions).start();
        restorer.stop();
        int calls = reads.get();

        Thread.sleep(LONG_ENOUGH_FOR_MANY_LOOKS.toMillis());

        assertThat(reads.get()).isEqualTo(calls);
    }

    private static int count(String text, String part) {
        int count = 0;
        for (int at = text.indexOf(part); at >= 0; at = text.indexOf(part, at + part.length())) {
            count++;
        }
        return count;
    }
}
