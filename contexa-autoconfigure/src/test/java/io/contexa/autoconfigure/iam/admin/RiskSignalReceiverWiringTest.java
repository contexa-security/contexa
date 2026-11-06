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
package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IForceLogoutService;
import io.contexa.contexacore.autonomous.signal.RiskSignalReceiver;
import io.contexa.contexacore.autonomous.signal.SecurityEventToken;
import io.contexa.contexacore.autonomous.signal.SecurityEventTokenVerifier;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/** The receiver the application gets reaches the forced logout it has: a receiver that works alone ends no token. */
class RiskSignalReceiverWiringTest {

    private final IForceLogoutService forceLogout = mock(IForceLogoutService.class);

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(IamAgentRegistryAutoConfiguration.RiskSignalReceiverConfiguration.class)
            .withPropertyValues("contexa.security.zerotrust.risk-signals.receiver-enabled=true")
            .withBean(ZeroTrustActionRepository.class, InMemoryZeroTrustActionRepository::new)
            .withBean(SecurityEventTokenVerifier.class, () -> mock(SecurityEventTokenVerifier.class));

    private static SecurityEventToken revokedSessionOf(String user) {
        return new SecurityEventToken("https://idp.example.test", "jti-1", Instant.now(),
                Map.of("format", "opaque", "id", user), Map.of(SecurityEventToken.SESSION_REVOKED, Map.of()));
    }

    @Test
    @DisplayName("an event that ends sessions reaches the forced logout of the application")
    void itReachesTheForcedLogout() {
        runner.withBean(IForceLogoutService.class, () -> forceLogout).run(context -> {
            context.getBean(RiskSignalReceiver.class).receive(revokedSessionOf("alice"));

            verify(forceLogout).forceLogoutByUserId(eq("alice"), anyString());
        });
    }

    @Test
    @DisplayName("without a forced logout the receiver still starts and answers")
    void withoutAForcedLogout() {
        runner.run(context -> assertThat(context.getBean(RiskSignalReceiver.class).receive(revokedSessionOf("alice"))
                .subjects()).containsExactly("alice"));
    }
}
