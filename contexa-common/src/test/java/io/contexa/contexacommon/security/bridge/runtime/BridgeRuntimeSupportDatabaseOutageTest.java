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
package io.contexa.contexacommon.security.bridge.runtime;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncResult;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

/** Contexa's database stops answering while the application is running: the signed-in request goes on without the user copy. */
class BridgeRuntimeSupportDatabaseOutageTest {

    private static final AuthenticationStamp SIGNED_IN = new AuthenticationStamp("user", "user", "USER", true, "BASIC", "HOST", null, null,
            Instant.now(), null, List.of("ROLE_USER"), Map.of());

    private final RequestPathDatabaseGuard guard = new RequestPathDatabaseGuard(Duration.ofMillis(150), 2);
    private final CountDownLatch databaseBack = new CountDownLatch(1);

    @AfterEach
    void release() {
        databaseBack.countDown();
        guard.destroy();
    }

    private BridgeRuntimeSupport supportWith(BridgeUserMirrorSyncService service) {
        return new BridgeRuntimeSupport(new BridgeProperties(), service, guard);
    }

    @Test
    void aMirrorThatDoesNotAnswerDoesNotHoldTheRequest() {
        BridgeRuntimeSupport support = supportWith((authentication, authorization, request) -> {
            try {
                databaseBack.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return null;
        });

        assertTimeoutPreemptively(Duration.ofSeconds(3), () -> assertThat(support.synchronizeUser(SIGNED_IN, null, null)).isNull());
    }

    @Test
    void aMirrorThatAnswersStillGivesTheRequestItsResult() {
        BridgeUserMirrorSyncResult result = new BridgeUserMirrorSyncResult(7L, "user", "user", "key", true, true, false, false);
        BridgeRuntimeSupport support = supportWith((authentication, authorization, request) -> result);

        assertThat(support.synchronizeUser(SIGNED_IN, null, null)).isEqualTo(result);
    }

    @Test
    void aMirrorThatFailsIsStillReadAsNoResult() {
        BridgeRuntimeSupport support = supportWith((authentication, authorization, request) -> {
            throw new IllegalStateException("connection refused");
        });

        assertThat(support.synchronizeUser(SIGNED_IN, null, null)).isNull();
    }
}
