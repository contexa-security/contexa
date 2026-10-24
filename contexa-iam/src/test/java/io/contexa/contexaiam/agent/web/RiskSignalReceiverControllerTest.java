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
package io.contexa.contexaiam.agent.web;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.signal.RiskSignalReceiver;
import io.contexa.contexacore.autonomous.signal.SecurityEventToken;
import io.contexa.contexacore.autonomous.signal.SecurityEventTokenVerifier;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** docs/agent A5-8 (RFC 8935): a verified token is acknowledged with 202 and acted on; another gets 400 and its error. */
class RiskSignalReceiverControllerTest {

    @Test
    void aVerifiedTokenIsAcknowledgedAndActedOnAndAnotherIsRefused() {
        InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
        actions.saveAction("alice", ZeroTrustAction.ALLOW, Map.of());
        SecurityEventTokenVerifier verifier = token -> {
            if (!"good".equals(token)) {
                throw new SecurityEventTokenVerifier.InvalidSecurityEventTokenException("invalid_key", "bad signature");
            }
            return new SecurityEventToken("https://idp.test", "jti-1", Instant.now(),
                    Map.of("format", "iss_sub", "iss", "https://idp.test", "sub", "alice"),
                    Map.of(SecurityEventToken.CREDENTIAL_CHANGE, Map.of()));
        };
        RiskSignalReceiverController controller = new RiskSignalReceiverController(verifier,
                new RiskSignalReceiver(actions, null, subjectId -> RiskSignalReceiver.userOf(subjectId, null), null));

        ResponseEntity<Map<String, String>> refused = controller.receive("forged");
        assertThat(refused.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(refused.getBody()).containsEntry("err", "invalid_key");
        assertThat(actions.getCurrentAction("alice")).isEqualTo(ZeroTrustAction.ALLOW);

        assertThat(controller.receive("good").getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(actions.getCurrentAction("alice")).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }
}
