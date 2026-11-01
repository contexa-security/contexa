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
package io.contexa.contexacore.autonomous.baseline.store;

import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.autonomous.baseline.LearningSubject;
import io.contexa.contexacore.autonomous.store.ExpiringKeySpace;
import io.contexa.contexacore.autonomous.store.ExpiringStateStore;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * In-memory baselines. Z-16 (F1): as in the Redis store, a baseline lasts the retention from its last save; past
 * 100,000 baselines of a kind the one saved the longest ago goes first, as Redis {@code volatile-ttl} evicts. The sweep
 * releases the baselines past the retention.
 */
public class InMemoryBaselineDataStore implements BaselineDataStore, ExpiringStateStore {

    private static final Duration DEFAULT_BASELINE_TTL = Duration.ofDays(30);
    private static final int DEFAULT_MAX_BASELINES = 100_000;

    private final ExpiringKeySpace<BaselineVector> userBaselines;
    private final ExpiringKeySpace<BaselineVector> orgBaselines;

    public InMemoryBaselineDataStore() {
        this(DEFAULT_BASELINE_TTL, Clock.systemUTC());
    }

    public InMemoryBaselineDataStore(Duration baselineTtl) {
        this(baselineTtl, Clock.systemUTC());
    }

    public InMemoryBaselineDataStore(Duration baselineTtl, Clock clock) {
        Objects.requireNonNull(clock, "clock");
        Duration ttl = Objects.requireNonNull(baselineTtl, "baselineTtl");
        this.userBaselines = buildSpace(ttl, clock);
        this.orgBaselines = buildSpace(ttl, clock);
    }

    @Override
    public BaselineVector getUserBaseline(String userId) {
        return userBaselines.get(userId);
    }

    @Override
    public void saveUserBaseline(String userId, BaselineVector baseline) {
        userBaselines.put(userId, baseline);
    }

    @Override
    public BaselineVector getOrganizationBaseline(String organizationId) {
        return orgBaselines.get(organizationId);
    }

    @Override
    public void saveOrganizationBaseline(String organizationId, BaselineVector baseline) {
        orgBaselines.put(organizationId, baseline);
    }

    @Override
    public Iterable<BaselineVector> listOrganizationBaselines() {
        orgBaselines.removeExpired();
        List<BaselineVector> live = new ArrayList<>();
        orgBaselines.forEach((organizationId, baseline) -> live.add(baseline));
        return live;
    }

    @Override
    public long countUserBaselines() {
        userBaselines.removeExpired();
        return userBaselines.size();
    }

    @Override
    public void deleteUserBaseline(String userId) {
        if (userId != null) {
            userBaselines.remove(userId);
            // The user's baselines under every tenant (W5-10 D9).
            userBaselines.removeIf(key -> key.endsWith(TENANT_SEPARATOR + userId));
            // docs/agent A3-1: the baselines of the agents acting for the user, in every tenant.
            String agentKeys = userId + LearningSubject.AGENT_KEY;
            userBaselines.removeIf(key -> key.startsWith(agentKeys)
                    || key.contains(TENANT_SEPARATOR + agentKeys));
        }
    }

    @Override
    public void deleteUserBaselineKey(String key) {
        if (key != null) {
            userBaselines.remove(key);
        }
    }

    @Override
    public int deleteAgentBaselines(String agentId) {
        if (agentId == null || agentId.isBlank()) {
            return 0;
        }
        String suffix = LearningSubject.AGENT_KEY + agentId;
        return userBaselines.removeIf(key -> key.endsWith(suffix));
    }

    @Override
    public void removeExpiredEntries() {
        userBaselines.removeExpired();
        orgBaselines.removeExpired();
    }

    private static ExpiringKeySpace<BaselineVector> buildSpace(Duration ttl, Clock clock) {
        return ExpiringKeySpace.<BaselineVector>builder(clock)
                .ttl(ttl)
                .bound(DEFAULT_MAX_BASELINES)
                .build();
    }
}
