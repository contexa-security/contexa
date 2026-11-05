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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every way a value enters, changes in or leaves a weighed space moves the bytes of its budget, the spaces of one
 * budget add up by key, and what goes for the limit is the key written the longest ago.
 */
class ExpiringKeySpaceBudgetTest {

    private final AdjustableClock clock = new AdjustableClock();
    private final List<String> evicted = new ArrayList<>();
    private final ExpiringKeyBudget budget = new ExpiringKeyBudget("test records", this::evict);
    private final ExpiringKeySpace<String> first = space();
    private final ExpiringKeySpace<String> second = space();

    private ExpiringKeySpace<String> space() {
        return ExpiringKeySpace.<String>builder(clock).ttl(Duration.ofMinutes(1))
                .weighed(budget, String::length).build();
    }

    private void evict(String key) {
        evicted.add(key);
        first.evict(key);
        second.evict(key);
    }

    @Test
    void theSpacesOfOneBudgetAddUpByKey() {
        first.put("a", "12345");
        second.put("a", "123");
        second.put("b", "12");

        assertThat(budget.bytes()).isEqualTo(10);
    }

    @Test
    void eachWriteMovesTheCountByWhatChanged() {
        first.put("a", "12345");
        first.put("a", "12");
        assertThat(budget.bytes()).isEqualTo(2);

        first.putIfAbsent("a", "1234567");
        assertThat(budget.bytes()).as("a live value stays").isEqualTo(2);

        first.compute("a", (key, value) -> value + "345");
        assertThat(budget.bytes()).isEqualTo(5);

        first.computeIfPresent("a", (key, value) -> "1");
        assertThat(budget.bytes()).isEqualTo(1);

        first.atomically("a", slot -> {
            slot.set("1234");
            return null;
        });
        assertThat(budget.bytes()).isEqualTo(4);

        first.getAndRefresh("a");
        assertThat(budget.bytes()).as("a read changes nothing").isEqualTo(4);
    }

    @Test
    void everyWayOutLeavesTheCount() {
        first.put("removed", "1");
        first.remove("removed");
        first.put("removed-by-value", "12");
        first.remove("removed-by-value", "12");
        first.put("removed-if", "123");
        first.removeIf(key -> key.equals("removed-if"));
        first.put("evicted", "1234");
        first.evict("evicted");
        first.put("deleted-by-a-script", "12345");
        first.atomically("deleted-by-a-script", slot -> {
            slot.delete();
            return null;
        });
        first.put("computed-away", "1");
        first.compute("computed-away", (key, value) -> null);

        assertThat(budget.bytes()).isZero();
    }

    @Test
    void anExpiredValueLeavesTheCountWhenAReadAWriteOrTheSweepMeetsIt() {
        first.put("read", "1");
        first.put("written", "12");
        first.put("swept", "123");
        clock.advance(Duration.ofMinutes(2));

        assertThat(first.get("read")).isNull();
        first.put("written", "1234");
        first.removeExpired();

        assertThat(budget.bytes()).isEqualTo(4);
    }

    @Test
    void pastTheLimitTheKeyWrittenTheLongestAgoGoesFromEverySpace() {
        budget.setLimitBytes(11);
        first.put("a", "12345");
        second.put("a", "1");
        first.put("b", "123");
        first.put("a", "1234");

        second.put("c", "123456");

        assertThat(evicted).containsExactly("b");
        assertThat(budget.bytes()).isEqualTo(11);
    }

    @Test
    void aKeyOverTheWholeLimitGoesAloneAndReleasesNoOther() {
        budget.setLimitBytes(10);
        first.put("a", "12345");

        first.put("b", "12345678901234");

        assertThat(evicted).containsExactly("b");
        assertThat(budget.bytes()).isEqualTo(5);
    }

    @Test
    void aWriteInsideAnUpdateLeavesTheLimitToTheNextWriteOutsideOne() {
        budget.setLimitBytes(4);
        first.put("a", "1234");

        second.compute("a", (key, value) -> {
            first.put("b", "123");
            assertThat(evicted).as("while a key is locked").isEmpty();
            return "1";
        });

        assertThat(evicted).isNotEmpty();
        assertThat(budget.bytes()).isLessThanOrEqualTo(4);
    }

    @Test
    void aSpaceWithoutABudgetMovesNothing() {
        ExpiringKeySpace<String> plain = ExpiringKeySpace.<String>builder(clock).ttl(Duration.ofMinutes(1)).build();

        plain.put("a", "12345");

        assertThat(budget.bytes()).isZero();
    }

    @Test
    void aLimitLoweredLaterIsMetAtOnce() {
        first.put("a", "12345");
        first.put("b", "12345");

        budget.setLimitBytes(5);

        assertThat(evicted).containsExactly("a");
        assertThat(budget.bytes()).isEqualTo(5);
    }

    @Test
    void aLimitNotPositiveIsTheDefault() {
        budget.setLimitBytes(0);

        assertThat(budget.limitBytes()).isEqualTo(ExpiringKeyBudget.defaultLimitBytes(Runtime.getRuntime().maxMemory()));
    }
}
