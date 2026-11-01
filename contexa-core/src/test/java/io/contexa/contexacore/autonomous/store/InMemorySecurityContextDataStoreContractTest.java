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

import java.time.Duration;

class InMemorySecurityContextDataStoreContractTest extends AbstractSecurityContextDataStoreContractTest {

    private final AdjustableClock clock = new AdjustableClock();

    @Override
    protected SecurityContextDataStore createStore() {
        return new InMemorySecurityContextDataStore(Duration.ofHours(24), Duration.ofDays(7), Duration.ofDays(7), clock);
    }

    @Override
    protected SecurityContextDataStore createStoreWithLoginFailureRetention(Duration retention) {
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();
        store.setLoginFailureRetention(retention);
        return store;
    }

    @Override
    protected SecurityContextDataStore createStoreWithObservationCapacity(int capacity) {
        InMemorySecurityContextDataStore store = new InMemorySecurityContextDataStore();
        store.setObservationCapacity(capacity);
        return store;
    }

    @Override
    protected SecurityContextDataStore createStoreWithEventProcessedTtl(Duration ttl) {
        return new InMemorySecurityContextDataStore(
                ttl,
                Duration.ofDays(7),
                Duration.ofDays(7));
    }

    @Override
    protected void passTime(Duration elapsed) {
        clock.advance(elapsed);
    }

    /** The only session risk of the test; a sweep first, so that a risk past its TTL is not counted. */
    @Override
    protected boolean holdsSessionRisk(String sessionId) {
        InMemorySecurityContextDataStore memory = (InMemorySecurityContextDataStore) store;
        memory.removeExpiredEntries();
        return memory.keyCounts().get("sessionRisks") > 0;
    }
}
