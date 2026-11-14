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

import io.contexa.contexacore.autonomous.signal.RiskSignalReceiver;
import io.contexa.contexacore.autonomous.signal.SecurityEventToken;
import io.contexa.contexacore.autonomous.signal.SecurityEventTokenVerifier;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The push endpoint of revocation and risk signals (docs/agent A5-8; RFC 8935 push delivery, OpenID SSF 1.0): a
 * transmitter posts a Security Event Token ({@code application/secevent+jwt}); a verified one is acknowledged with 202
 * and its subjects are decided again, one that does not verify gets 400 with the RFC 8935 error. The application's
 * policy lets the transmitter reach the endpoint (its client's token); the token's signature is what is trusted.
 */
@Slf4j
@RestController
@RequestMapping("/contexa/api/risk-signals")
public class RiskSignalReceiverController {

    private final SecurityEventTokenVerifier verifier;
    private final RiskSignalReceiver receiver;

    public RiskSignalReceiverController(SecurityEventTokenVerifier verifier, RiskSignalReceiver receiver) {
        this.verifier = verifier;
        this.receiver = receiver;
    }

    @PostMapping(consumes = {"application/secevent+jwt", "application/jwt", "text/plain"})
    public ResponseEntity<DeliveryError> receive(@RequestBody(required = false) String token) {
        SecurityEventToken verified;
        try {
            verified = verifier.verify(token);
        } catch (SecurityEventTokenVerifier.InvalidSecurityEventTokenException e) {
            log.warn("A risk signal was refused: error={}, description={}", e.error(), e.getMessage());
            return ResponseEntity.badRequest().body(new DeliveryError(e.error(), e.getMessage()));
        }
        receiver.receive(verified);
        return ResponseEntity.status(HttpStatus.ACCEPTED).build();
    }
}
