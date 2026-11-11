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
package io.contexa.contexacommon.security.bridge.runtime;

import com.github.benmanes.caffeine.cache.Ticker;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationEffect;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncResult;
import io.contexa.contexacommon.store.ContexaStores;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.sql.SQLTransientConnectionException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

/** What is kept of a user's copy: for the very facts it was answered for, for a bounded time and number of subjects. */
class UserCopyMemoryTest {

    private static final BridgeUserMirrorSyncResult ALICE_COPY =
            new BridgeUserMirrorSyncResult(7L, "brg_alice", "alice", "key-alice", true, true, true, true);

    private final AtomicLong now = new AtomicLong();
    private final Ticker ticker = now::get;
    private UserCopyMemory memory = new UserCopyMemory(Duration.ofSeconds(60), 100, ticker);

    @AfterEach
    void close() {
        memory.close();
    }

    @Test
    void whatIsKeptIsGivenBackForTheSameFactsAsAFoundCopy() {
        memory.remember(facts("alice", "203.0.113.5", "s-1", Instant.parse("2026-11-11T00:00:00Z")), ALICE_COPY);

        UserCopyMemory.Kept kept = memory.recall(facts("alice", "203.0.113.5", "s-1", Instant.parse("2026-11-11T00:00:00Z")));

        assertThat(kept).isNotNull();
        assertThat(kept.result().internalUserId()).isEqualTo(7L);
        assertThat(kept.result().created()).as("nothing was created for a later request").isFalse();
        assertThat(kept.result().updated()).isFalse();
    }

    /** The synchronisation compares neither the session nor the time of the sign-in before it writes, and neither does this. */
    @Test
    void aNewSessionOfTheSameUserFindsTheCopyKept() {
        memory.remember(facts("alice", "203.0.113.5", "s-1", Instant.parse("2026-11-11T00:00:00Z")), ALICE_COPY);

        assertThat(memory.recall(facts("alice", "203.0.113.5", "s-2", Instant.parse("2026-11-11T00:05:00Z")))).isNotNull();
    }

    @Test
    void anotherAddressAnotherNameOrOtherAuthoritiesAreNotTheSameFacts() {
        memory.remember(facts("alice", "203.0.113.5", "s-1", null), ALICE_COPY);

        assertThat(memory.recall(facts("alice", "198.51.100.7", "s-1", null))).isNull();
        assertThat(memory.recall(withAuthorities("alice", "ROLE_USER", "ROLE_ADMIN"))).isNull();
        assertThat(memory.recall(facts("bob", "203.0.113.5", "s-1", null))).as("another user").isNull();
    }

    @Test
    void whatIsKeptExpires() {
        memory.remember(facts("alice", "203.0.113.5", "s-1", null), ALICE_COPY);

        now.addAndGet(TimeUnit.SECONDS.toNanos(59));
        assertThat(memory.recall(facts("alice", "203.0.113.5", "s-1", null))).isNotNull();
        now.addAndGet(TimeUnit.SECONDS.toNanos(2));
        assertThat(memory.recall(facts("alice", "203.0.113.5", "s-1", null))).isNull();
    }

    @Test
    void theNumberOfSubjectsKeptIsBounded() {
        memory.close();
        memory = new UserCopyMemory(Duration.ofSeconds(60), 3, ticker);
        for (int i = 0; i < 50; i++) {
            memory.remember(facts("user-" + i, "203.0.113.5", "s-1", null), ALICE_COPY);
        }

        assertThat(memory.keptSubjects()).isLessThanOrEqualTo(3);
        assertThat(new UserCopyMemory(Duration.ofSeconds(60)).keptSubjects()).isZero();
        assertThat(UserCopyMemory.MAXIMUM_SUBJECTS).isEqualTo(10_000);
    }

    @Test
    void nothingIsKeptWhenTheCopyIsToBeWrittenOnEveryRequest() {
        memory.close();
        memory = new UserCopyMemory(Duration.ZERO, 100, ticker);
        memory.remember(facts("alice", "203.0.113.5", "s-1", null), ALICE_COPY);

        assertThat(memory.recall(facts("alice", "203.0.113.5", "s-1", null))).isNull();
    }

    @Test
    void aValueThatCannotBeComparedKeepsNothingAndFailsNothing() {
        memory.remember(UserCopyMemory.Facts.of(hostile(), null, request("203.0.113.5", "s-1")), ALICE_COPY);

        assertThat(memory.recall(UserCopyMemory.Facts.of(hostile(), null, request("203.0.113.5", "s-1")))).isNull();
    }

    @Test
    void anAuthenticationWithoutASubjectHasNoFacts() {
        AuthenticationStamp nameless = new AuthenticationStamp("  ", null, null, true, null, null, null, null, null, null,
                List.of(), Map.of());

        assertThat(UserCopyMemory.Facts.of(nameless, null, null)).isNull();
    }

    @Test
    void oneSynchronisationOfASubjectAtATimeAndWhatItAnswersIsKept() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger runs = new AtomicInteger();
        UserCopyMemory.Facts facts = facts("alice", "203.0.113.5", "s-1", null);
        for (int i = 0; i < 5; i++) {
            memory.synchroniseAway(facts, () -> {
                runs.incrementAndGet();
                awaitQuietly(release);
                return Optional.of(ALICE_COPY);
            });
        }
        release.countDown();
        awaitKept(facts);

        assertThat(runs).hasValue(1);
        assertThat(memory.recall(facts).result().internalUserId()).isEqualTo(7L);
    }

    @Test
    void aSynchronisationThatGotNoAnswerKeepsNothingAndTheNextOneRuns() throws Exception {
        UserCopyMemory.Facts facts = facts("alice", "203.0.113.5", "s-1", null);
        CountDownLatch first = new CountDownLatch(1);
        memory.synchroniseAway(facts, () -> {
            first.countDown();
            return null;
        });
        assertThat(first.await(5, TimeUnit.SECONDS)).isTrue();
        Thread.sleep(50);
        assertThat(memory.recall(facts)).isNull();

        memory.synchroniseAway(facts, () -> Optional.of(ALICE_COPY));
        awaitKept(facts);
    }

    /** No copy for the facts (an empty answer) is an answer: it is kept, and asked again only when it expires. */
    @Test
    void anAnswerOfNoCopyIsKept() throws Exception {
        UserCopyMemory.Facts facts = facts("alice", "203.0.113.5", "s-1", null);
        memory.synchroniseAway(facts, Optional::empty);
        awaitKept(facts);

        assertThat(memory.recall(facts).result()).isNull();
    }

    /** Contexa's database is down: the request's guard answers at once, nothing is kept, and the request was never held. */
    @Test
    void anOutageOfTheDatabaseIsSkippedAtOnceAndKeepsNothing() throws Exception {
        ContexaStores stores = new ContexaStores();
        stores.database().watchWith(() -> {
            throw new IllegalStateException("still down");
        });
        stores.database().fail(new SQLTransientConnectionException("connection refused"));
        RequestPathDatabaseGuard guard = new RequestPathDatabaseGuard(Duration.ofSeconds(1), 2, stores.database());
        AtomicInteger asked = new AtomicInteger();
        BridgeRuntimeSupport support = new BridgeRuntimeSupport(new BridgeProperties(), (a, z, r) -> {
            asked.incrementAndGet();
            return ALICE_COPY;
        }, guard);
        AuthenticationStamp alice = new AuthenticationStamp("alice", "Alice", "USER", true, "FORM", "SECURITY_CONTEXT",
                null, null, null, null, List.of("ROLE_USER"), Map.of());
        try {
            assertThat(stores.database().isDown()).isTrue();
            long started = System.nanoTime();
            assertThat(support.synchronizeUser(null, alice, null, request("203.0.113.5", null), false)).isNull();
            assertThat(support.synchronizeUser(alice, null, request("203.0.113.5", null))).isNull();
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofMillis(500));
            Thread.sleep(100);
            assertThat(asked).as("the database is not asked while it is down").hasValue(0);
        } finally {
            support.destroy();
            guard.destroy();
            stores.destroy();
        }
    }

    private void awaitKept(UserCopyMemory.Facts facts) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (memory.recall(facts) == null && System.nanoTime() < deadline) {
            Thread.sleep(10);
        }
        assertThat(memory.recall(facts)).isNotNull();
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static UserCopyMemory.Facts facts(String subject, String address, String session, Instant signedInAt) {
        AuthenticationStamp authentication = new AuthenticationStamp(subject, subject, "USER", true, "FORM",
                "SECURITY_CONTEXT", null, null, signedInAt, session, List.of("ROLE_USER"), Map.of("department", "sales"));
        return UserCopyMemory.Facts.of(authentication, authorization(subject), request(address, session));
    }

    private static UserCopyMemory.Facts withAuthorities(String subject, String... authorities) {
        AuthenticationStamp authentication = new AuthenticationStamp(subject, subject, "USER", true, "FORM",
                "SECURITY_CONTEXT", null, null, null, "s-1", List.of(authorities), Map.of("department", "sales"));
        return UserCopyMemory.Facts.of(authentication, authorization(subject), request("203.0.113.5", "s-1"));
    }

    private static AuthorizationStamp authorization(String subject) {
        return new AuthorizationStamp(subject, "/orders", "GET", AuthorizationEffect.UNKNOWN, null, List.of(), null, null,
                "AUTHENTICATION_DERIVED", Instant.now(), List.of("ROLE_USER"), List.of("ROLE_USER"),
                Map.of("authorizationResolver", "AUTHENTICATION_DERIVED"));
    }

    private static RequestContextSnapshot request(String address, String session) {
        return new RequestContextSnapshot("/orders", "GET", address, "ua", session, "r-" + System.nanoTime(), "/orders",
                null, false, Instant.now());
    }

    private static AuthenticationStamp hostile() {
        return new AuthenticationStamp("alice", "Alice", "USER", true, "FORM", "SECURITY_CONTEXT", null, null, null, "s-1",
                List.of("ROLE_USER"), Map.of("profile", new Uncomparable()));
    }

    /** A value of the application's whose comparison fails. */
    private static final class Uncomparable {

        @Override
        public boolean equals(Object other) {
            throw new IllegalStateException("not comparable");
        }

        @Override
        public int hashCode() {
            return 1;
        }
    }
}
