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
package io.contexa.autoconfigure.core.infra;

import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.baseline.store.InMemoryBaselineDataStore;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.SmartInitializingSingleton;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

/**
 * QF-32: reports at startup that the learned state is kept in memory. The default infrastructure mode, standalone,
 * selects the in-memory baseline store and the in-memory store of the work profile observations and the held
 * learnings, so a restart starts every user's learning again. One warning line names the in-memory stores in use; a
 * store the host gives keeps the startup silent. Nothing else changes.
 */
@Slf4j
public class StandaloneLearningStateWarning implements SmartInitializingSingleton {

    private final Supplier<BaselineDataStore> baselineDataStore;
    private final Supplier<SecurityContextDataStore> securityContextDataStore;

    public StandaloneLearningStateWarning(Supplier<BaselineDataStore> baselineDataStore,
                                          Supplier<SecurityContextDataStore> securityContextDataStore) {
        this.baselineDataStore = baselineDataStore;
        this.securityContextDataStore = securityContextDataStore;
    }

    @Override
    public void afterSingletonsInstantiated() {
        List<String> inMemory = inMemoryStores();
        if (!inMemory.isEmpty()) {
            log.warn("[Contexa] contexa.infrastructure.mode is standalone: the learned state is kept in memory and lost "
                    + "on restart ({}); standalone is for development, set contexa.infrastructure.mode=distributed "
                    + "with Redis to keep the learned baselines, observations and held learnings.",
                    String.join(", ", inMemory));
        }
    }

    /** The in-memory stores of the learned state in use, by their class names. */
    List<String> inMemoryStores() {
        List<String> stores = new ArrayList<>();
        if (baselineDataStore.get() instanceof InMemoryBaselineDataStore) {
            stores.add(InMemoryBaselineDataStore.class.getSimpleName());
        }
        if (securityContextDataStore.get() instanceof InMemorySecurityContextDataStore) {
            stores.add(InMemorySecurityContextDataStore.class.getSimpleName());
        }
        return stores;
    }
}
