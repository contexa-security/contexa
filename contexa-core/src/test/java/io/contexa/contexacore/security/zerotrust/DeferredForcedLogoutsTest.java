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
package io.contexa.contexacore.security.zerotrust;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.dao.QueryTimeoutException;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/** What waits for Redis, in the order it was asked, within a bound that says when it is passed. */
@ExtendWith(OutputCaptureExtension.class)
class DeferredForcedLogoutsTest {

    private final List<String> applied = new ArrayList<>();
    private final DeferredForcedLogouts deferred = new DeferredForcedLogouts(3);

    @Test
    void theLogoutsAreAppliedInTheOrderTheyWereAsked() {
        deferred.defer("alice", "ACCOUNT_DISABLED");
        deferred.defer("bob", "ACCOUNT_DELETED");

        deferred.applyAll((user, reason) -> applied.add(user + ":" + reason));

        assertThat(applied).containsExactly("alice:ACCOUNT_DISABLED", "bob:ACCOUNT_DELETED");
        assertThat(deferred.size()).isZero();
    }

    @Test
    void oneUserWaitsOnceWithTheReasonAskedLast() {
        deferred.defer("alice", "ACCOUNT_DISABLED");
        deferred.defer("alice", "ACCOUNT_DELETED");

        deferred.applyAll((user, reason) -> applied.add(user + ":" + reason));

        assertThat(applied).containsExactly("alice:ACCOUNT_DELETED");
    }

    @Test
    void anOutageStopsThePassAndKeepsWhatItDidNotReach() {
        deferred.defer("alice", "r");
        deferred.defer("bob", "r");
        deferred.defer("carol", "r");

        deferred.applyAll((user, reason) -> {
            if ("bob".equals(user)) {
                throw new QueryTimeoutException("no answer");
            }
            applied.add(user);
        });

        assertThat(applied).containsExactly("alice");
        assertThat(deferred.size()).isEqualTo(2);
    }

    @Test
    void aLogoutThatCannotBeAppliedForAnotherReasonDoesNotHoldTheOthers(CapturedOutput output) {
        deferred.defer("alice", "r");
        deferred.defer("bob", "r");

        deferred.applyAll((user, reason) -> {
            if ("alice".equals(user)) {
                throw new IllegalStateException("a bug");
            }
            applied.add(user);
        });

        assertThat(applied).containsExactly("bob");
        assertThat(deferred.size()).isZero();
        assertThat(output).contains("could not be applied").contains("alice");
    }

    @Test
    void pastTheBoundTheLogoutAskedFirstIsDroppedAndSaid(CapturedOutput output) {
        deferred.defer("alice", "r");
        deferred.defer("bob", "r");
        deferred.defer("carol", "r");

        deferred.defer("dave", "r");

        assertThat(deferred.size()).isEqualTo(3);
        deferred.applyAll((user, reason) -> applied.add(user));
        assertThat(applied).containsExactly("bob", "carol", "dave");
        assertThat(output).contains("alice").contains("will not be applied");
    }

    @Test
    void aLogoutAskedAgainDuringThePassIsNotLost() {
        deferred.defer("alice", "first");

        deferred.applyAll((user, reason) -> deferred.defer("alice", "second"));

        assertThat(deferred.size()).isEqualTo(1);
    }

    @Test
    void passesDoNotOverlap() throws Exception {
        deferred.defer("alice", "r");
        CountDownLatch inside = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger passes = new AtomicInteger();
        ExecutorService other = Executors.newSingleThreadExecutor();
        Future<?> first = other.submit(() -> deferred.applyAll((user, reason) -> {
            passes.incrementAndGet();
            inside.countDown();
            try {
                release.await();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        }));
        inside.await();

        deferred.applyAll((user, reason) -> passes.incrementAndGet());
        release.countDown();
        first.get();
        other.shutdown();

        assertThat(passes).hasValue(1);
    }

    @RepeatedTest(5)
    void everyUserAskedAtOnceIsAppliedOnceItIsAsked() throws Exception {
        DeferredForcedLogouts wide = new DeferredForcedLogouts(10_000);
        Set<String> done = ConcurrentHashMap.newKeySet();
        ExecutorService writers = Executors.newFixedThreadPool(4);
        List<Future<?>> running = new ArrayList<>();
        for (int writer = 0; writer < 4; writer++) {
            int from = writer * 500;
            running.add(writers.submit(() -> {
                for (int user = from; user < from + 500; user++) {
                    wide.defer("user-" + user, "r");
                    if (user % 50 == 0) {
                        wide.applyAll((name, reason) -> done.add(name));
                    }
                }
            }));
        }
        for (Future<?> writer : running) {
            writer.get();
        }
        writers.shutdown();

        wide.applyAll((name, reason) -> done.add(name));

        assertThat(done).hasSize(2_000);
        assertThat(wide.size()).isZero();
    }
}
