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
package io.contexa.contexaidentity.security.core.mfa.policy.evaluator;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/** The stored decision at a password step on the store of a single server. */
class InMemoryStoredDecisionSignInTest extends AbstractStoredDecisionSignInContractTest {

    private final MovedClock clock = new MovedClock();
    private final InMemoryZeroTrustActionRepository store = new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock);

    @Override
    protected ZeroTrustActionRepository store() {
        return store;
    }

    @Override
    protected void analysisRunsOut(String user) {
        clock.moved = clock.moved.plus(ZeroTrustAction.ALLOW.getDefaultTtl()).plusSeconds(1);
    }

    private static final class MovedClock extends Clock {

        private Duration moved = Duration.ZERO;

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return Instant.now().plus(moved);
        }
    }
}
