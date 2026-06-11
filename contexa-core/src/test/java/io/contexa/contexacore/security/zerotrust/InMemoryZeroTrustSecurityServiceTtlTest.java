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

import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.blocking.InMemoryBlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.InMemoryThreatScoreUtil;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryZeroTrustSecurityServiceTtlTest {

    private InMemoryZeroTrustSecurityService create(Duration invalidationTtl) {
        SecurityZeroTrustProperties props = new SecurityZeroTrustProperties();
        ThreatScoreUtil scoreUtil = new InMemoryThreatScoreUtil(props);
        ZeroTrustActionRepository actionRepository = new InMemoryZeroTrustActionRepository();
        BlockingSignalBroadcaster broadcaster = new InMemoryBlockingSignalBroadcaster();
        return new InMemoryZeroTrustSecurityService(
                scoreUtil, props, actionRepository, broadcaster, invalidationTtl);
    }

    @Test
    @DisplayName("isSessionInvalidated reports true right after invalidateSession")
    void invalidationVisibleImmediately() {
        InMemoryZeroTrustSecurityService service = create(Duration.ofMinutes(5));

        service.invalidateSession("sid-fresh", "user-a", "manual");

        assertThat(service.isSessionInvalidated("sid-fresh")).isTrue();
    }

    @Test
    @DisplayName("Invalidated session entry expires after the configured TTL")
    void invalidationExpiresAfterTtl() {
        InMemoryZeroTrustSecurityService service = create(Duration.ofMillis(200));

        service.invalidateSession("sid-ttl", "user-a", "manual");
        assertThat(service.isSessionInvalidated("sid-ttl")).isTrue();

        Awaitility.await()
                .atMost(Duration.ofSeconds(5))
                .pollInterval(Duration.ofMillis(100))
                .untilAsserted(() -> assertThat(service.isSessionInvalidated("sid-ttl"))
                        .as("in-memory invalidation state must self-expire to match Redis TTL behaviour")
                        .isFalse());
    }
}
