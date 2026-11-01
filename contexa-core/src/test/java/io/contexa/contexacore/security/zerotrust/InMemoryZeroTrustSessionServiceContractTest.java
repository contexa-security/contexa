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
package io.contexa.contexacore.security.zerotrust;

import io.contexa.contexacore.autonomous.blocking.InMemoryBlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;

import java.time.Duration;

import static org.mockito.Mockito.mock;

class InMemoryZeroTrustSessionServiceContractTest extends AbstractZeroTrustSessionServiceContractTest {

    private final InMemorySecurityContextDataStore contextStore = new InMemorySecurityContextDataStore(
            Duration.ofHours(24), Duration.ofDays(7), Duration.ofDays(7), clock);

    @Override
    protected AbstractZeroTrustSecurityService createService(SecurityZeroTrustProperties properties) {
        return new InMemoryZeroTrustSecurityService(mock(ThreatScoreUtil.class), properties,
                new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock),
                new InMemoryBlockingSignalBroadcaster(), contextStore, clock);
    }

    @Override
    protected SecurityContextDataStore contextStore() {
        return contextStore;
    }

    @Override
    protected void elapse(Duration elapsed) {
        clock.advance(elapsed);
    }
}
