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
package io.contexa.contexacore.autonomous.store;

import io.contexa.contexacore.testsupport.AdjustableClock;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Z-16 (N-1): the key space keeps, extends and forgets its keys as Redis does, and keeps its bound by expiry.
 */
class ExpiringKeySpaceTest {

    private static final Duration TTL = Duration.ofMinutes(10);

    private final AdjustableClock clock = new AdjustableClock();
    private final List<String> removed = new ArrayList<>();

    private ExpiringKeySpace<String> space() {
        return ExpiringKeySpace.<String>builder(clock).ttl(TTL).onRemoved(removed::add).build();
    }

    @Test
    void aValueReadPastItsExpiryIsAbsentAndGoesAtOnce() {
        ExpiringKeySpace<String> space = space();
        space.put("a", "value");

        clock.advance(TTL.minusSeconds(1));
        assertThat(space.get("a")).isEqualTo("value");
        clock.advance(Duration.ofSeconds(1));

        assertThat(space.get("a")).isNull();
        assertThat(space.containsKey("a")).isFalse();
        assertThat(space.holds("a")).as("removed by the read, before any sweep").isFalse();
        assertThat(removed).containsExactly("value");
    }

    @Test
    void onlyARefreshingReadExtendsAValueAndOnlyWhileItLives() {
        ExpiringKeySpace<String> space = space();
        space.put("a", "value");

        clock.advance(Duration.ofMinutes(9));
        assertThat(space.get("a")).as("a plain read").isEqualTo("value");
        assertThat(space.getAndRefresh("a")).isEqualTo("value");
        clock.advance(Duration.ofMinutes(9));
        assertThat(space.get("a")).as("refreshed nine minutes ago").isEqualTo("value");
        clock.advance(Duration.ofMinutes(2));

        assertThat(space.getAndRefresh("a")).as("not revived").isNull();
        assertThat(space.get("a")).isNull();
    }

    @Test
    void aWriteAfterTheExpiryStartsAnewAndTheExpiredValueGoesToOnRemoved() {
        ExpiringKeySpace<String> space = space();
        space.put("a", "old");
        clock.advance(TTL);

        String held = space.compute("a", (key, current) -> current == null ? "new" : current + "+new");

        assertThat(held).isEqualTo("new");
        assertThat(removed).containsExactly("old");
    }

    @Test
    void aChangeThatKeepsTheExpiryAndASetIfAbsentDoNotExtendIt() {
        ExpiringKeySpace<String> space = space();
        space.put("a", "first");
        clock.advance(Duration.ofMinutes(6));

        assertThat(space.putIfAbsent("a", "second")).isFalse();
        assertThat(space.computeIfPresent("a", (key, current) -> current + "+changed")).isEqualTo("first+changed");
        clock.advance(Duration.ofMinutes(4));

        assertThat(space.get("a")).isNull();
        assertThat(space.putIfAbsent("a", "third")).as("held again once expired").isTrue();
        assertThat(space.get("a")).isEqualTo("third");
        assertThat(space.computeIfPresent("missing", (key, current) -> "never")).isNull();
        assertThat(space.holds("missing")).isFalse();
    }

    @Test
    void aWriteSetsTheExpiryAnewAndAWriteWithItsOwnTtlKeepsIt() {
        ExpiringKeySpace<String> space = space();
        long start = clock.millis();
        space.put("a", "value", Duration.ofSeconds(15));

        assertThat(space.expiresAtMs("a")).isBetween(start + 15_000, clock.millis() + 15_000);
        space.compute("a", (key, current) -> current + "+again");
        assertThat(space.expiresAtMs("a")).isGreaterThanOrEqualTo(start + TTL.toMillis());
        assertThat(space.expiresAtMs("missing")).isZero();
    }

    @Test
    void theSweepRemovesTheExpiredValuesOnlyAndTellsOfEach() {
        ExpiringKeySpace<String> space = space();
        space.put("early", "1");
        space.put("late", "2", Duration.ofHours(1));
        space.put("also-early", "3");
        clock.advance(TTL);

        assertThat(space.removeExpired()).isEqualTo(2);

        assertThat(space.size()).isEqualTo(1);
        assertThat(space.get("late")).isEqualTo("2");
        assertThat(removed).containsExactlyInAnyOrder("1", "3");
    }

    @Test
    void pastTheBoundTheKeysWhoseExpiryComesFirstGoAndAKeyWrittenAgainStays() {
        ExpiringKeySpace<String> space = ExpiringKeySpace.<String>builder(clock).ttl(TTL).bound(100)
                .onRemoved(removed::add).build();
        for (int key = 0; key < 100; key++) {
            space.put("key-" + key, "value-" + key);
            clock.advance(Duration.ofMillis(1));
        }
        // Written again, the first ten now expire last.
        for (int key = 0; key < 10; key++) {
            space.put("key-" + key, "again-" + key);
            clock.advance(Duration.ofMillis(1));
        }
        for (int key = 100; key < 120; key++) {
            space.put("key-" + key, "value-" + key);
            clock.advance(Duration.ofMillis(1));
        }

        assertThat(space.size()).isEqualTo(100);
        for (int key = 0; key < 10; key++) {
            assertThat(space.get("key-" + key)).isEqualTo("again-" + key);
        }
        for (int key = 10; key < 30; key++) {
            assertThat(space.get("key-" + key)).as("key-%d", key).isNull();
        }
        for (int key = 30; key < 120; key++) {
            assertThat(space.get("key-" + key)).as("key-%d", key).isNotNull();
        }
        assertThat(removed).hasSize(20).allMatch(value -> value.startsWith("value-"));
    }

    @Test
    void aKeyTheOwnerKeepsOutOfTheBoundNeverGoesForIt() {
        Set<String> restricted = Set.of("restricted-0", "restricted-1");
        ExpiringKeySpace<String> space = ExpiringKeySpace.<String>builder(clock).ttl(TTL).bound(10)
                .evictable(key -> !restricted.contains(key)).build();
        space.put("restricted-0", "block");
        space.put("restricted-1", "block");
        clock.advance(Duration.ofMillis(1));
        for (int key = 0; key < 20; key++) {
            space.put("key-" + key, "value");
            clock.advance(Duration.ofMillis(1));
        }

        assertThat(space.size()).isEqualTo(10);
        assertThat(space.get("restricted-0")).isEqualTo("block");
        assertThat(space.get("restricted-1")).isEqualTo("block");
        for (int key = 12; key < 20; key++) {
            assertThat(space.get("key-" + key)).as("key-%d", key).isEqualTo("value");
        }
    }

    @Test
    void aSpaceOfKeysThatMayNotGoGrowsPastItsBoundAndKeepsThemAll() {
        ExpiringKeySpace<String> space = ExpiringKeySpace.<String>builder(clock).ttl(TTL).bound(10)
                .evictable(key -> false).build();
        for (int key = 0; key < 50; key++) {
            space.put("restricted-" + key, "block");
        }

        assertThat(space.size()).isEqualTo(50);
        assertThat(space.keys()).hasSize(50);
    }

    @Test
    void anOwnerCanEvictAKeyTogetherWithWhatItKeepsElsewhere() {
        List<ExpiringKeySpace<String>> together = new ArrayList<>();
        ExpiringKeySpace<String> other = space();
        ExpiringKeySpace<String> bounded = ExpiringKeySpace.<String>builder(clock).ttl(TTL).bound(2)
                .evictWith(key -> together.forEach(space -> space.evict(key))).build();
        together.add(bounded);
        together.add(other);
        for (String key : List.of("s-1", "s-2", "s-3")) {
            bounded.put(key, "record");
            other.put(key, "companion-" + key);
            clock.advance(Duration.ofMillis(1));
        }

        assertThat(bounded.get("s-1")).isNull();
        assertThat(other.get("s-1")).isNull();
        assertThat(removed).as("what goes with the evicted key is told too").containsExactly("companion-s-1");
        assertThat(other.get("s-3")).isEqualTo("companion-s-3");
    }

    @Test
    void aScriptOnOneKeySetsKeepsAndDeletesTogether() {
        ExpiringKeySpace<String> space = ExpiringKeySpace.<String>builder(clock).build();
        long deadline = clock.millis() + Duration.ofMinutes(30).toMillis();

        space.atomically("a", slot -> {
            slot.setUntil("first", deadline);
            return null;
        });
        String seen = space.atomically("a", slot -> {
            slot.keep(slot.value() + "+second");
            // A later deadline extends it, an earlier one does not (a deadline never shortens).
            slot.expireAt(Math.max(slot.expiresAtMs(), deadline - 1_000));
            return slot.value();
        });
        assertThat(seen).isEqualTo("first+second");
        assertThat(space.expiresAtMs("a")).isEqualTo(deadline);

        Boolean deleted = space.atomically("a", slot -> {
            slot.delete();
            return slot.value() == null;
        });
        assertThat(deleted).isTrue();
        assertThat(space.holds("a")).isFalse();
        String missing = space.atomically("missing", slot -> slot.value());
        assertThat(missing).isNull();
        assertThat(space.holds("missing")).isFalse();
    }

    @Test
    void anOwnerReleasesOnlyWhatItHoldsAndAMatchingRemovalCountsTheLiveValues() {
        ExpiringKeySpace<String> space = space();
        space.put("lock", "owner-1");
        space.put("user::a", "1");
        space.put("user::b", "2", Duration.ofMillis(1));
        space.put("other", "3");
        clock.advance(Duration.ofMillis(1));

        assertThat(space.remove("lock", "owner-2")).isFalse();
        assertThat(space.remove("lock", "owner-1")).isTrue();
        List<String> taken = new ArrayList<>();
        assertThat(space.removeIf(key -> key.startsWith("user::"), taken::add)).isEqualTo(1);
        assertThat(taken).containsExactly("1");
        assertThat(removed).as("the expired one is told as expired").containsExactly("2");
        assertThat(space.keys()).containsExactly("other");
    }

    @Test
    void aWriteInsideAnotherSpacesUpdateLeavesTheBoundToTheNextWriteOutsideOne() {
        ExpiringKeySpace<String> outer = space();
        ExpiringKeySpace<String> inner = ExpiringKeySpace.<String>builder(clock).ttl(TTL).bound(2).build();
        inner.put("i-1", "1");
        clock.advance(Duration.ofMillis(1));
        inner.put("i-2", "2");
        clock.advance(Duration.ofMillis(1));

        outer.compute("o", (key, current) -> {
            inner.put("i-3", "3");
            return "outer";
        });
        assertThat(inner.size()).as("not trimmed inside the update").isEqualTo(3);

        clock.advance(Duration.ofMillis(1));
        inner.put("i-4", "4");
        assertThat(inner.size()).isEqualTo(2);
        assertThat(inner.keys()).containsExactlyInAnyOrder("i-3", "i-4");
    }
}
