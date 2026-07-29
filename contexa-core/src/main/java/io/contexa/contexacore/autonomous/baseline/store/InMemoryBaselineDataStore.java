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

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacommon.security.baseline.BaselineVector;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class InMemoryBaselineDataStore implements BaselineDataStore {

    private static final Duration DEFAULT_BASELINE_TTL = Duration.ofDays(30);
    private static final long DEFAULT_MAX_BASELINES = 100_000L;

    private final Cache<String, BaselineVector> userBaselines;
    private final Cache<String, BaselineVector> orgBaselines;

    public InMemoryBaselineDataStore() {
        this(DEFAULT_BASELINE_TTL, Clock.systemUTC());
    }

    public InMemoryBaselineDataStore(Duration baselineTtl) {
        this(baselineTtl, Clock.systemUTC());
    }

    public InMemoryBaselineDataStore(Duration baselineTtl, Clock clock) {
        Objects.requireNonNull(clock, "clock");
        Duration ttl = Objects.requireNonNull(baselineTtl, "baselineTtl");
        this.userBaselines = buildCache(ttl);
        this.orgBaselines = buildCache(ttl);
    }

    @Override
    public BaselineVector getUserBaseline(String userId) {
        return userBaselines.getIfPresent(userId);
    }

    @Override
    public void saveUserBaseline(String userId, BaselineVector baseline) {
        userBaselines.put(userId, baseline);
    }

    @Override
    public BaselineVector getOrganizationBaseline(String organizationId) {
        return orgBaselines.getIfPresent(organizationId);
    }

    @Override
    public void saveOrganizationBaseline(String organizationId, BaselineVector baseline) {
        orgBaselines.put(organizationId, baseline);
    }

    @Override
    public Iterable<BaselineVector> listOrganizationBaselines() {
        orgBaselines.cleanUp();
        List<BaselineVector> live = new ArrayList<>();
        live.addAll(orgBaselines.asMap().values());
        return live;
    }

    @Override
    public long countUserBaselines() {
        userBaselines.cleanUp();
        return userBaselines.estimatedSize();
    }

    private Cache<String, BaselineVector> buildCache(Duration ttl) {
        return Caffeine.newBuilder()
                .expireAfterWrite(ttl)
                .maximumSize(DEFAULT_MAX_BASELINES)
                .build();
    }
}
