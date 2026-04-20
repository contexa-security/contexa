package io.contexa.contexacore.hcad.store;

import io.contexa.contexacommon.hcad.domain.BaselineVector;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryBaselineDataStore implements BaselineDataStore {

    private static final Duration DEFAULT_BASELINE_TTL = Duration.ofDays(30);

    private final ConcurrentHashMap<String, Entry> userBaselines = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Entry> orgBaselines = new ConcurrentHashMap<>();
    private final Duration baselineTtl;
    private final Clock clock;

    public InMemoryBaselineDataStore() {
        this(DEFAULT_BASELINE_TTL, Clock.systemUTC());
    }

    public InMemoryBaselineDataStore(Duration baselineTtl) {
        this(baselineTtl, Clock.systemUTC());
    }

    public InMemoryBaselineDataStore(Duration baselineTtl, Clock clock) {
        this.baselineTtl = Objects.requireNonNull(baselineTtl, "baselineTtl");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public BaselineVector getUserBaseline(String userId) {
        return resolveLiveEntry(userBaselines, userId);
    }

    @Override
    public void saveUserBaseline(String userId, BaselineVector baseline) {
        userBaselines.put(userId, new Entry(baseline, clock.instant().plus(baselineTtl)));
    }

    @Override
    public BaselineVector getOrganizationBaseline(String organizationId) {
        return resolveLiveEntry(orgBaselines, organizationId);
    }

    @Override
    public void saveOrganizationBaseline(String organizationId, BaselineVector baseline) {
        orgBaselines.put(organizationId, new Entry(baseline, clock.instant().plus(baselineTtl)));
    }

    @Override
    public Iterable<BaselineVector> listOrganizationBaselines() {
        Instant now = clock.instant();
        List<BaselineVector> live = new ArrayList<>();
        orgBaselines.entrySet().removeIf(e -> now.isAfter(e.getValue().expiresAt));
        for (Entry e : orgBaselines.values()) {
            if (!now.isAfter(e.expiresAt)) {
                live.add(e.baseline);
            }
        }
        return live;
    }

    @Override
    public long countUserBaselines() {
        Instant now = clock.instant();
        userBaselines.entrySet().removeIf(e -> now.isAfter(e.getValue().expiresAt));
        return userBaselines.size();
    }

    private BaselineVector resolveLiveEntry(ConcurrentHashMap<String, Entry> map, String key) {
        Entry entry = map.get(key);
        if (entry == null) {
            return null;
        }
        if (clock.instant().isAfter(entry.expiresAt)) {
            map.remove(key, entry);
            return null;
        }
        return entry.baseline;
    }

    private static final class Entry {
        final BaselineVector baseline;
        final Instant expiresAt;

        Entry(BaselineVector baseline, Instant expiresAt) {
            this.baseline = baseline;
            this.expiresAt = expiresAt;
        }
    }
}
