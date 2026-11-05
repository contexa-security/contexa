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

import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * The bytes one kind of in-memory record may take together, for the heap of the application, which Redis
 * leaves to its own memory limit. The {@link ExpiringKeySpace}s weighed against it add up by key, so that a session's
 * records in several spaces are one session here. Past the limit the key written the longest ago goes whole, which is
 * the order Redis {@code volatile-ttl} evicts keys of one TTL in, and a key larger than the whole limit goes first and
 * releases no other. Nothing below the limit changes what is kept, so what a decision reads differs only past it, and the
 * first key to go in a minute is reported.
 * <p>
 * The lock is taken last and nothing is called under it: the spaces call in while a key is locked.
 */
@Slf4j
public final class ExpiringKeyBudget {

    private static final int HEAP_SHARE_DIVISOR = 20;
    private static final long MIN_DEFAULT_BYTES = 16L * 1024 * 1024;
    private static final long MAX_DEFAULT_BYTES = 512L * 1024 * 1024;
    private static final long REPORT_INTERVAL_MS = Duration.ofMinutes(1).toMillis();

    private final String name;
    private final Consumer<String> evictor;
    /** What each key is counted at, the key written the longest ago first. */
    private final Map<String, Long> keys = new LinkedHashMap<>();
    private long bytes;
    /** The key a write took past the whole limit, which goes before any older one. */
    private String oversized;
    private long keysReleased;
    private long reportedAtMs;
    private volatile long limitBytes = defaultLimitBytes(Runtime.getRuntime().maxMemory());

    /**
     * @param name    what the records are, for the report
     * @param evictor removes a key from every space weighed here, with {@link ExpiringKeySpace#evict}
     */
    public ExpiringKeyBudget(String name, Consumer<String> evictor) {
        this.name = name;
        this.evictor = evictor;
    }

    /**
     * The default limit for a maximum heap of {@code maxHeapBytes}: a twentieth of it, between 16 MiB and 512 MiB. A
     * 384 MiB heap gives 19.2 MiB, 2 GiB 102.4 MiB, 10 GiB or more and a JVM without a heap limit 512 MiB.
     */
    public static long defaultLimitBytes(long maxHeapBytes) {
        return Math.max(MIN_DEFAULT_BYTES, Math.min(MAX_DEFAULT_BYTES, maxHeapBytes / HEAP_SHARE_DIVISOR));
    }

    /** The limit, met at once; not positive, {@link #defaultLimitBytes(long) the one derived from the maximum heap}. */
    public void setLimitBytes(long limitBytes) {
        this.limitBytes = limitBytes > 0 ? limitBytes : defaultLimitBytes(Runtime.getRuntime().maxMemory());
        keepWithinLimit();
    }

    public long limitBytes() {
        return limitBytes;
    }

    /** What the records take now, as counted against the limit. */
    public synchronized long bytes() {
        return bytes;
    }

    /** A write moved the key's bytes by {@code change}: the key is now the one written last. */
    synchronized void written(String key, long change) {
        Long held = keys.remove(key);
        long before = held != null ? held : 0L;
        long after = Math.max(0L, before + change);
        bytes += after - before;
        if (after > 0L) {
            keys.put(key, after);
            if (after > limitBytes) {
                oversized = key;
            }
        }
    }

    /** {@code gone} bytes of the key left; the key keeps its place. A key that went for the limit counts for nothing. */
    synchronized void left(String key, long gone) {
        Long held = keys.get(key);
        if (held == null) {
            return;
        }
        long after = Math.max(0L, held - gone);
        bytes -= held - after;
        if (after > 0L) {
            keys.put(key, after);
        } else {
            keys.remove(key);
        }
    }

    /** Lets keys go until the records are within the limit. Called outside any update of a space. */
    void keepWithinLimit() {
        String key;
        while ((key = nextToGo()) != null) {
            evictor.accept(key);
        }
    }

    /** Takes the next key to go out of the count, or says none is left to go. */
    private synchronized String nextToGo() {
        if (bytes <= limitBytes || keys.isEmpty()) {
            return null;
        }
        String key = oversized != null && keys.containsKey(oversized) ? oversized : oldest();
        oversized = null;
        bytes -= keys.remove(key);
        keysReleased++;
        long now = System.currentTimeMillis();
        if (now - reportedAtMs >= REPORT_INTERVAL_MS) {
            reportedAtMs = now;
            log.warn("[Contexa] The {} kept in memory reached their limit of {} bytes, a share of the heap: {} of the keys "
                    + "written the longest ago were dropped since the start, and later decisions read less of them. "
                    + "contexa.infrastructure.mode=distributed keeps them in Redis.", name, limitBytes, keysReleased);
        }
        return key;
    }

    private String oldest() {
        Iterator<String> order = keys.keySet().iterator();
        return order.next();
    }
}
