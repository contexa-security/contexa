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

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.PriorityQueue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.ToLongFunction;

/**
 * Z-16 (N-1): one kind of in-memory state whose keys expire as the keys of a Redis store do, so that an in-memory store
 * and its Redis twin keep, read and forget the same things.
 * <ul>
 * <li>Every key has its own expiry. A read checks it: an expired value reads as absent and is removed there and then,
 * as Redis expires a key a command touches (lazy expiry). {@link #removeExpired()}, which the owning store's sweep
 * calls, removes the expired values no read met (active expiry).</li>
 * <li>A write sets its key's expiry anew, as a Redis write followed by EXPIRE does. Only {@link #getAndRefresh} extends
 * it on a read, for the keys the Redis store extends on a read. A change that keeps the expiry
 * ({@link #computeIfPresent}, {@link Slot#keep}) is a Redis change that leaves the TTL (HDEL, SET KEEPTTL), and
 * {@link #putIfAbsent} leaves a live value and its expiry as they are (SET NX).</li>
 * <li>An optional bound keeps the space within a number of keys, for the memory of the JVM, as Redis
 * {@code volatile-ttl} eviction does: past it the keys whose expiry comes first go first, so the records written most
 * recently stay. The owner keeps out of it the keys that must not go for memory (a restriction must not be lifted by
 * it), and may say how a key goes (with what it keeps for the key elsewhere).</li>
 * <li>A value the space removes by itself, expired or evicted for the bound, is handed to {@code onRemoved}; a value the
 * owner removes is returned to the owner instead.</li>
 * <li>An optional {@link ExpiringKeyBudget} keeps the values within a number of bytes, for the same memory: every
 * value that enters, changes or leaves moves it here, whichever way it does.</li>
 * </ul>
 * A function given to an update runs while its key is locked and must not update this same space. A write made inside
 * the function of another space's update leaves the bound to the next write made outside one, or to the sweep.
 *
 * @param <V> the values, never null
 */
public final class ExpiringKeySpace<V> {

    /** How deep the calling thread is in the functions of updates, of any space: a bound is kept only outside them. */
    private static final ThreadLocal<int[]> UPDATE_DEPTH = ThreadLocal.withInitial(() -> new int[1]);

    private final ConcurrentHashMap<String, Entry<V>> entries = new ConcurrentHashMap<>();
    private final Clock clock;
    private final Duration ttl;
    private final Consumer<? super V> onRemoved;
    private final int maxKeys;
    private final Predicate<String> evictable;
    private final Consumer<String> evictor;
    private final ExpiringKeyBudget budget;
    private final ToLongFunction<? super V> weigher;
    /** The keys chosen to go next for the bound, earliest expiry first; guarded by {@link #trimLock}. */
    private final ArrayDeque<TrimCandidate> candidates = new ArrayDeque<>();
    private final ReentrantLock trimLock = new ReentrantLock();
    /**
     * Past the bound without a key that may go: the size from which the next pass looks again, so that a space of keys
     * that may not go costs a pass a tenth of the bound's writes at most; 0 otherwise. Guarded by {@link #trimLock}.
     */
    private int nextChooseSize;

    private ExpiringKeySpace(Builder<V> builder) {
        this.clock = builder.clock;
        this.ttl = builder.ttl;
        this.onRemoved = builder.onRemoved;
        this.maxKeys = builder.maxKeys;
        this.evictable = builder.evictable;
        this.evictor = builder.evictor;
        this.budget = builder.budget;
        this.weigher = builder.weigher;
    }

    /** A space reading the time from {@code clock}; see {@link Builder}. */
    public static <V> Builder<V> builder(Clock clock) {
        return new Builder<>(clock);
    }

    /** GET: the live value, its expiry unchanged; null when there is none. An expired value is removed. */
    public V get(String key) {
        Entry<V> entry = entries.get(key);
        if (entry == null) {
            return null;
        }
        if (entry.expired(clock.millis())) {
            dropExpired(key, entry);
            return null;
        }
        return entry.value;
    }

    /** GET then EXPIRE: the live value, its expiry set anew with the space's TTL; null when there is none. */
    public V getAndRefresh(String key) {
        return getAndRefresh(key, requireTtl());
    }

    /** GET then PEXPIRE: the live value, expiring {@code ttl} from now; null when there is none. */
    public V getAndRefresh(String key, Duration ttl) {
        long nowMs = clock.millis();
        long expiresAtMs = expiryAfter(nowMs, ttl);
        Entry<V> refreshed = entries.computeIfPresent(key, (held, entry) -> {
            if (entry.expired(nowMs)) {
                counted(held, entry, null);
                removed(entry.value);
                return null;
            }
            return new Entry<>(entry.value, expiresAtMs, entry.weight);
        });
        return refreshed == null ? null : refreshed.value;
    }

    /** EXISTS: whether the key holds a live value. */
    public boolean containsKey(String key) {
        return get(key) != null;
    }

    /** When the key's live value expires, in epoch milliseconds (PTTL as a time); 0 without a live value. */
    public long expiresAtMs(String key) {
        Entry<V> entry = entries.get(key);
        if (entry == null) {
            return 0;
        }
        if (entry.expired(clock.millis())) {
            dropExpired(key, entry);
            return 0;
        }
        return entry.expiresAtMs;
    }

    /** SET EX: holds the value for the space's TTL; the live value it replaced, or null. */
    public V put(String key, V value) {
        return put(key, value, requireTtl());
    }

    /** SET PX: holds the value for {@code ttl}; the live value it replaced, or null. */
    public V put(String key, V value, Duration ttl) {
        Objects.requireNonNull(value, "value");
        long nowMs = clock.millis();
        Entry<V> written = entryOf(value, expiryAfter(nowMs, ttl));
        Entry<V> previous = entries.put(key, written);
        counted(key, previous, written);
        trimToBound();
        if (previous == null) {
            return null;
        }
        if (previous.expired(nowMs)) {
            removed(previous.value);
            return null;
        }
        return previous.value;
    }

    /** SET NX EX: holds the value for the space's TTL unless the key holds a live one; whether it was held. */
    public boolean putIfAbsent(String key, V value) {
        return putIfAbsent(key, value, requireTtl());
    }

    /**
     * SET NX PX: holds the value for {@code ttl} unless the key holds a live one, whose value and expiry then stay as
     * they are; whether it was held.
     */
    public boolean putIfAbsent(String key, V value, Duration ttl) {
        Objects.requireNonNull(value, "value");
        long nowMs = clock.millis();
        long expiresAtMs = expiryAfter(nowMs, ttl);
        boolean[] held = new boolean[1];
        entries.compute(key, (heldKey, entry) -> {
            if (entry != null && !entry.expired(nowMs)) {
                return entry;
            }
            if (entry != null) {
                removed(entry.value);
            }
            held[0] = true;
            Entry<V> written = entryOf(value, expiresAtMs);
            counted(heldKey, entry, written);
            return written;
        });
        if (held[0]) {
            trimToBound();
        }
        return held[0];
    }

    /**
     * A write from the key's live value (null when there is none), as a Redis change followed by EXPIRE: a value the
     * function returns is held for the space's TTL, null removes the key. The value held, or null.
     */
    public V compute(String key, BiFunction<String, ? super V, ? extends V> remapping) {
        return compute(key, remapping, requireTtl());
    }

    /** {@link #compute(String, BiFunction)} with the value held for {@code ttl}. */
    public V compute(String key, BiFunction<String, ? super V, ? extends V> remapping, Duration ttl) {
        Objects.requireNonNull(remapping, "remapping");
        long nowMs = clock.millis();
        long expiresAtMs = expiryAfter(nowMs, ttl);
        Entry<V> next = entries.compute(key, (held, entry) -> {
            V current = null;
            if (entry != null) {
                if (entry.expired(nowMs)) {
                    removed(entry.value);
                } else {
                    current = entry.value;
                }
            }
            V value = apply(remapping, held, current);
            Entry<V> written = value == null ? null : entryOf(value, expiresAtMs);
            counted(held, entry, written);
            return written;
        });
        trimToBound();
        return next == null ? null : next.value;
    }

    /**
     * A change of the key's live value that keeps its expiry, as a Redis change without EXPIRE (HDEL, LREM, SET
     * KEEPTTL); null removes the key. Nothing without a live value. The value held, or null.
     */
    public V computeIfPresent(String key, BiFunction<String, ? super V, ? extends V> remapping) {
        Objects.requireNonNull(remapping, "remapping");
        long nowMs = clock.millis();
        Entry<V> next = entries.computeIfPresent(key, (held, entry) -> {
            if (entry.expired(nowMs)) {
                counted(held, entry, null);
                removed(entry.value);
                return null;
            }
            V value = apply(remapping, held, entry.value);
            if (value == null) {
                counted(held, entry, null);
                return null;
            }
            Entry<V> written = value == entry.value && weigher == null ? entry : entryOf(value, entry.expiresAtMs);
            counted(held, entry, written);
            return written;
        });
        keepWithinBudget();
        return next == null ? null : next.value;
    }

    /**
     * Any Redis commands on one key, applied at once as a script on the key would apply them: the function reads the
     * live value and says what the key holds after it through the {@link Slot}; what it returns is returned.
     */
    public <R> R atomically(String key, Function<? super Slot<V>, ? extends R> script) {
        Objects.requireNonNull(script, "script");
        long nowMs = clock.millis();
        List<R> result = new ArrayList<>(1);
        boolean[] written = new boolean[1];
        entries.compute(key, (held, entry) -> {
            Entry<V> live = entry;
            if (entry != null && entry.expired(nowMs)) {
                removed(entry.value);
                live = null;
            }
            KeySlot slot = new KeySlot(live, nowMs);
            enterUpdate();
            try {
                result.add(script.apply(slot));
            } finally {
                exitUpdate();
            }
            Entry<V> next = slot.next();
            written[0] = next != null && next != live;
            if (next != entry) {
                counted(held, entry, next);
            }
            return next;
        });
        if (written[0]) {
            trimToBound();
        }
        return result.isEmpty() ? null : result.get(0);
    }

    /** DEL: the live value removed, or null. */
    public V remove(String key) {
        Entry<V> entry = entries.remove(key);
        if (entry == null) {
            return null;
        }
        counted(key, entry, null);
        if (entry.expired(clock.millis())) {
            removed(entry.value);
            return null;
        }
        return entry.value;
    }

    /** Removes the key when its live value equals {@code value}, as an owner releases what it holds; whether it did. */
    public boolean remove(String key, Object value) {
        long nowMs = clock.millis();
        boolean[] released = new boolean[1];
        entries.computeIfPresent(key, (held, entry) -> {
            if (entry.expired(nowMs)) {
                counted(held, entry, null);
                removed(entry.value);
                return null;
            }
            if (!Objects.equals(entry.value, value)) {
                return entry;
            }
            counted(held, entry, null);
            released[0] = true;
            return null;
        });
        return released[0];
    }

    /** Removes the keys that match; how many live values went (as a SCAN and DEL count the live keys). */
    public int removeIf(Predicate<String> keyMatches) {
        return removeIf(keyMatches, value -> {
        });
    }

    /**
     * Removes the keys that match, handing each live value removed to {@code removedValue} while its key is locked;
     * how many live values went.
     */
    public int removeIf(Predicate<String> keyMatches, Consumer<? super V> removedValue) {
        Objects.requireNonNull(keyMatches, "keyMatches");
        Objects.requireNonNull(removedValue, "removedValue");
        long nowMs = clock.millis();
        int[] count = new int[1];
        for (String key : entries.keySet()) {
            if (!keyMatches.test(key)) {
                continue;
            }
            entries.computeIfPresent(key, (held, entry) -> {
                counted(held, entry, null);
                if (entry.expired(nowMs)) {
                    removed(entry.value);
                    return null;
                }
                count[0]++;
                enterUpdate();
                try {
                    removedValue.accept(entry.value);
                } finally {
                    exitUpdate();
                }
                return null;
            });
        }
        return count[0];
    }

    /**
     * Removes the key's value as the bound does: the value, live or expired, goes to {@code onRemoved}. For an owner
     * whose keys leave several spaces together ({@link Builder#evictWith}).
     */
    public void evict(String key) {
        Entry<V> entry = entries.remove(key);
        if (entry != null) {
            counted(key, entry, null);
            removed(entry.value);
        }
    }

    /** The keys holding a live value when called. */
    public Set<String> keys() {
        long nowMs = clock.millis();
        Set<String> live = new LinkedHashSet<>();
        entries.forEach((key, entry) -> {
            if (!entry.expired(nowMs)) {
                live.add(key);
            }
        });
        return live;
    }

    /** Calls {@code action} with each key and its live value, the space's own value rather than a copy. */
    public void forEach(BiConsumer<String, ? super V> action) {
        Objects.requireNonNull(action, "action");
        long nowMs = clock.millis();
        entries.forEach((key, entry) -> {
            if (!entry.expired(nowMs)) {
                action.accept(key, entry.value);
            }
        });
    }

    /** How many keys the space holds, expired values no read or sweep removed yet included (as Redis DBSIZE). */
    public int size() {
        return entries.size();
    }

    /** Whether the key holds a value, expired or not: whether the space still takes memory for it. */
    public boolean holds(String key) {
        return entries.containsKey(key);
    }

    /**
     * The active expiry: removes every expired value, each handed to {@code onRemoved}, then keeps the bound. Safe
     * against concurrent writers: a value written again meanwhile stays. How many values expired.
     */
    public int removeExpired() {
        long nowMs = clock.millis();
        int[] expired = new int[1];
        for (Map.Entry<String, Entry<V>> held : entries.entrySet()) {
            if (!held.getValue().expired(nowMs)) {
                continue;
            }
            entries.computeIfPresent(held.getKey(), (key, entry) -> {
                if (!entry.expired(nowMs)) {
                    return entry;
                }
                expired[0]++;
                counted(key, entry, null);
                removed(entry.value);
                return null;
            });
        }
        if (maxKeys > 0 && trimLock.tryLock()) {
            try {
                // A key that may not go for the bound may by now (a restriction lifted).
                nextChooseSize = 0;
            } finally {
                trimLock.unlock();
            }
        }
        trimToBound();
        return expired[0];
    }

    /**
     * Keeps the space within its bound, the keys whose expiry comes first going first; a key written again since it
     * was chosen, or one the owner keeps out of the bound, stays. Nothing without a bound, inside the function of an
     * update, or while another thread keeps the bound. Every write that adds a key calls it.
     */
    public void trimToBound() {
        keepWithinBudget();
        if (maxKeys <= 0 || entries.size() <= maxKeys || UPDATE_DEPTH.get()[0] > 0 || !trimLock.tryLock()) {
            return;
        }
        try {
            for (int pass = 0; pass < 2 && entries.size() > maxKeys; pass++) {
                if (candidates.isEmpty() && !choose()) {
                    return;
                }
                TrimCandidate candidate;
                while (entries.size() > maxKeys && (candidate = candidates.pollFirst()) != null) {
                    evictIfUnchanged(candidate);
                }
            }
        } finally {
            trimLock.unlock();
        }
    }

    /** Chooses the next keys to go: the excess or a tenth of the bound, earliest expiry first; whether any may go. */
    private boolean choose() {
        int size = entries.size();
        if (size < nextChooseSize) {
            return false;
        }
        int wanted = Math.max(size - maxKeys, Math.max(1, maxKeys / 10));
        // The latest of the earliest on top, so that a key expiring earlier takes its place.
        PriorityQueue<TrimCandidate> earliest = new PriorityQueue<>(
                Comparator.comparingLong(TrimCandidate::expiresAtMs).reversed());
        for (Map.Entry<String, Entry<V>> held : entries.entrySet()) {
            String key = held.getKey();
            long expiresAtMs = held.getValue().expiresAtMs;
            if (earliest.size() < wanted) {
                if (evictable.test(key)) {
                    earliest.add(new TrimCandidate(key, expiresAtMs));
                }
            } else if (expiresAtMs < earliest.peek().expiresAtMs() && evictable.test(key)) {
                earliest.poll();
                earliest.add(new TrimCandidate(key, expiresAtMs));
            }
        }
        if (earliest.isEmpty()) {
            nextChooseSize = size + Math.max(1, maxKeys / 10);
            return false;
        }
        nextChooseSize = 0;
        List<TrimCandidate> chosen = new ArrayList<>(earliest);
        chosen.sort(Comparator.comparingLong(TrimCandidate::expiresAtMs));
        candidates.addAll(chosen);
        return true;
    }

    private void evictIfUnchanged(TrimCandidate candidate) {
        String key = candidate.key();
        if (!evictable.test(key)) {
            return;
        }
        if (evictor != null) {
            Entry<V> entry = entries.get(key);
            if (entry != null && entry.expiresAtMs == candidate.expiresAtMs()) {
                evictor.accept(key);
            }
            return;
        }
        entries.computeIfPresent(key, (held, entry) -> {
            if (entry.expiresAtMs != candidate.expiresAtMs()) {
                return entry;
            }
            counted(held, entry, null);
            removed(entry.value);
            return null;
        });
    }

    private void dropExpired(String key, Entry<V> entry) {
        if (entries.remove(key, entry)) {
            counted(key, entry, null);
            removed(entry.value);
        }
    }

    private Entry<V> entryOf(V value, long expiresAtMs) {
        return new Entry<>(value, expiresAtMs, weigher != null ? weigher.applyAsLong(value) : 0L);
    }

    /** The key's {@code previous} entry was replaced with {@code next}, or left when there is none. */
    private void counted(String key, Entry<V> previous, Entry<V> next) {
        if (budget == null) {
            return;
        }
        long before = previous != null ? previous.weight : 0L;
        if (next != null) {
            budget.written(key, next.weight - before);
        } else if (previous != null) {
            budget.left(key, before);
        }
    }

    /** Lets keys go for the budget, outside the functions of updates: going takes other keys' locks. */
    private void keepWithinBudget() {
        if (budget != null && UPDATE_DEPTH.get()[0] == 0) {
            budget.keepWithinLimit();
        }
    }

    private void removed(V value) {
        enterUpdate();
        try {
            onRemoved.accept(value);
        } finally {
            exitUpdate();
        }
    }

    private V apply(BiFunction<String, ? super V, ? extends V> remapping, String key, V current) {
        enterUpdate();
        try {
            return remapping.apply(key, current);
        } finally {
            exitUpdate();
        }
    }

    private Duration requireTtl() {
        if (ttl == null) {
            throw new IllegalStateException("The key space has no TTL of its own: a write gives one");
        }
        return ttl;
    }

    private static long expiryAfter(long nowMs, Duration ttl) {
        long ttlMs = Objects.requireNonNull(ttl, "ttl").toMillis();
        return ttlMs >= Long.MAX_VALUE - nowMs ? Long.MAX_VALUE : nowMs + ttlMs;
    }

    private static void enterUpdate() {
        UPDATE_DEPTH.get()[0]++;
    }

    private static void exitUpdate() {
        UPDATE_DEPTH.get()[0]--;
    }

    /**
     * One key inside {@link #atomically}: its live value and the Redis commands on it, applied together when the
     * function returns. Without a call the key stays as it is.
     */
    public interface Slot<V> {

        /** The live value; null when the key holds none, or held one that expired. */
        V value();

        /** When the live value expires, in epoch milliseconds; 0 without a live value. */
        long expiresAtMs();

        /** SET EX: the value, for the space's TTL. */
        void set(V value);

        /** SET PX: the value, for {@code ttl}. */
        void set(V value, Duration ttl);

        /** SET PXAT: the value, until {@code expiresAtMs} in epoch milliseconds (a deadline). */
        void setUntil(V value, long expiresAtMs);

        /** SET KEEPTTL: the value, the live value's expiry kept; without a live value, for the space's TTL. */
        void keep(V value);

        /** PEXPIRE: the live value expires {@code ttl} from now; nothing without one. */
        void expire(Duration ttl);

        /** PEXPIREAT: the live value expires at {@code expiresAtMs}; nothing without one. */
        void expireAt(long expiresAtMs);

        /** DEL. */
        void delete();
    }

    /**
     * What a space is made of: the clock, and optionally its TTL, who is told of the values it removes by itself, and
     * its bound.
     */
    public static final class Builder<V> {

        private final Clock clock;
        private Duration ttl;
        private Consumer<? super V> onRemoved = value -> {
        };
        private int maxKeys;
        private Predicate<String> evictable = key -> true;
        private Consumer<String> evictor;
        private ExpiringKeyBudget budget;
        private ToLongFunction<? super V> weigher;

        private Builder(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
        }

        /** The TTL of a write that gives none; without it every write gives one. */
        public Builder<V> ttl(Duration ttl) {
            this.ttl = Objects.requireNonNull(ttl, "ttl");
            return this;
        }

        /**
         * Told of each value the space removes by itself, expired or evicted for the bound, while its key is locked:
         * it must not update this space.
         */
        public Builder<V> onRemoved(Consumer<? super V> onRemoved) {
            this.onRemoved = Objects.requireNonNull(onRemoved, "onRemoved");
            return this;
        }

        /** Keeps the space within {@code maxKeys} keys, the keys whose expiry comes first going first. */
        public Builder<V> bound(int maxKeys) {
            if (maxKeys < 1) {
                throw new IllegalArgumentException("maxKeys must be positive: " + maxKeys);
            }
            this.maxKeys = maxKeys;
            return this;
        }

        /**
         * Which keys may go for the bound, asked when they are chosen and again before they go; the others stay
         * whatever the size (a restriction must not be lifted for memory).
         */
        public Builder<V> evictable(Predicate<String> evictable) {
            this.evictable = Objects.requireNonNull(evictable, "evictable");
            return this;
        }

        /**
         * How a key goes for the bound when it is not only this space's: the owner removes it with {@link #evict}
         * together with what it keeps for the key elsewhere. Without it the key leaves this space alone.
         */
        public Builder<V> evictWith(Consumer<String> evictor) {
            this.evictor = Objects.requireNonNull(evictor, "evictor");
            return this;
        }

        /**
         * Counts every value against {@code budget} at what {@code weigher} says, in bytes. The weigher is asked
         * each time the value is written and must answer at once: it runs while the key is locked.
         */
        public Builder<V> weighed(ExpiringKeyBudget budget, ToLongFunction<? super V> weigher) {
            this.budget = Objects.requireNonNull(budget, "budget");
            this.weigher = Objects.requireNonNull(weigher, "weigher");
            return this;
        }

        public ExpiringKeySpace<V> build() {
            return new ExpiringKeySpace<>(this);
        }
    }

    /**
     * A value, when it expires, in epoch milliseconds, and what it was counted at when written; an entry is replaced,
     * never changed.
     */
    private static final class Entry<V> {

        private final V value;
        private final long expiresAtMs;
        private final long weight;

        private Entry(V value, long expiresAtMs, long weight) {
            this.value = value;
            this.expiresAtMs = expiresAtMs;
            this.weight = weight;
        }

        private boolean expired(long nowMs) {
            return nowMs >= expiresAtMs;
        }
    }

    /** A key chosen to go when the space passes its bound, with the expiry it had then. */
    private record TrimCandidate(String key, long expiresAtMs) {
    }

    private final class KeySlot implements Slot<V> {

        private final Entry<V> live;
        private final long nowMs;
        private V value;
        private long expiresAtMs;

        private KeySlot(Entry<V> live, long nowMs) {
            this.live = live;
            this.nowMs = nowMs;
            this.value = live != null ? live.value : null;
            this.expiresAtMs = live != null ? live.expiresAtMs : 0;
        }

        @Override
        public V value() {
            return value;
        }

        @Override
        public long expiresAtMs() {
            return value != null ? expiresAtMs : 0;
        }

        @Override
        public void set(V value) {
            set(value, requireTtl());
        }

        @Override
        public void set(V value, Duration ttl) {
            setUntil(value, expiryAfter(nowMs, ttl));
        }

        @Override
        public void setUntil(V value, long expiresAtMs) {
            this.value = Objects.requireNonNull(value, "value");
            this.expiresAtMs = expiresAtMs;
        }

        @Override
        public void keep(V value) {
            if (this.value == null) {
                set(value);
                return;
            }
            this.value = Objects.requireNonNull(value, "value");
        }

        @Override
        public void expire(Duration ttl) {
            if (value != null) {
                expiresAtMs = expiryAfter(nowMs, ttl);
            }
        }

        @Override
        public void expireAt(long expiresAtMs) {
            if (value != null) {
                this.expiresAtMs = expiresAtMs;
            }
        }

        @Override
        public void delete() {
            value = null;
            expiresAtMs = 0;
        }

        private Entry<V> next() {
            if (value == null) {
                return null;
            }
            if (live != null && value == live.value && expiresAtMs == live.expiresAtMs) {
                return live;
            }
            return entryOf(value, expiresAtMs);
        }
    }
}
